# Scoped 0.1 migration

`ColophonMigration` is part of the root **ColophonSDK** package and depends only on
`ColophonSession`. It has no imports or dependencies on the 0.1 reference modules.
An app supplies a `LegacyLibrarySource` implemented over **its own** 0.1 stack. This is the
boundary for Marginalia's complete Later codecs and service folds; linking the reference
adapter into Marginalia would bring back the colliding 0.1 module names.

The optional `ColophonLegacyAdapter` product lives in `reference/swift/Package.swift`. It uses
that package's real authority verifier, replica, identities and domain folds. Its saved-reading
fold remains a subset of Later's. Missing codecs remain unresolved evidence, never guessed effects.

## Construct an upgrade

For a fixture or consumer of the reference package:

```swift
import ColophonLegacyAdapter
import ColophonMigration

let source = ColophonLegacyAdapter(
    store: oldStore, readerIdentity: existingReader, rootIdentity: existingRoot)
let migration = LibraryMigration(
    source: source, namespaces: ["reading.books"], destination: migrationSession,
    privateContainer: booksMigrationDirectory, evidenceKey: persistedEvidenceKey,
    markerURL: booksMarkerURL)
var report = try await migration.run(batchSize: 64)
while report.remainingOperations > 0 {
    report = try await migration.run(batchSize: 64)
}
```

Marginalia substitutes its own `LegacyLibrarySource` here and adds only the root SDK's products
alongside its local `packages/Colophon` dependency. See [package identity steps](native-bindings.md#package-identity-and-coexistence-with-01).
The source adapter owns the reader and root providers; the SDK does not accept 0.1 identity types.

The explicit scope is a nonempty set drawn from `reading.books`, `reading.saved`,
`listening.podcasts`, and `notes`. Invalid scopes fail before asking the adapter to read.
`run`, progress counts, evidence queries, import commands and completion all use this scope.
A books-only migration can finish while valid saved-reading records remain in the old library,
even when this reference implementation cannot interpret their kinds. No old files are changed,
no old member grants are copied, and no source namespace is marked globally migrated.

Use a dedicated root-owned destination session with `migrationWriter: true`. Its configured
namespaces must include the scope. Never expose that writer as the product UI session; give
ordinary app members their own keys and narrowly scoped grants through normal enrollment.
Source-root possession does not confer destination authority: the destination engine separately
requires the signing provider to be its root.

By default the first run requires an empty destination. To import a later namespace into an
already-created shared 0.2 library, pass `destinationLibraryID: expectedID` and use a fresh
scope-specific journal directory. The ID must match the open destination before any destination
write; a typo or a missing library fails closed. That shared destination must already declare
all intended namespaces and its root must have access to them. Alternatively each app can
migrate into a separate destination, without needing grants to the other namespaces.

Keep one durable directory and one marker URL per fixed scope. All product sessions gated by
that scope use that marker. Apps still using other 0.1 namespaces keep their existing lifecycle;
they must not treat completion of books as completion of the whole suite. Do not reuse one
marker for independent concurrent migrations: one could clear another's barrier. Serialize
migration writers that share a destination. An app consuming several independently migrated
scopes must coordinate their barriers before presenting ready content (the session takes one
marker URL). A whole-suite migration can instead use one scope containing all four namespaces.

The journal is bound to source library ID, the sorted namespace set and destination library ID.
Changing scope or source under a journal fails. Preserve the AES key, journal and archive across
restarts. Pre-restructure journals lack the scope field and cannot be resumed by this version;
keep their original implementation and artifacts for reconciliation rather than deleting them
or replaying over an existing destination.

## Adapter contract

The public definitions are in
[`LegacyLibrarySource.swift`](../swift/Sources/ColophonMigration/LegacyLibrarySource.swift).
Both protocols are `Sendable`; returning an object with mutable live source state violates the
contract. Implement the following behavior:

1. `snapshot(namespaces:)` makes an immutable, internally consistent snapshot of the requested
   namespaces and the authority needed to verify them. Verify the complete 0.1 authority chain,
   library identity, current source root, signatures over the original signed bytes, envelope
   author/namespace/epoch binding, decryption and operation identity. Prove possession of the
   current root with a fresh signed challenge. The reference adapter performs all these checks
   and never writes its source store. Missing authority, keys or requested namespace access
   must throw; an inaccessible namespace is not an empty namespace.
2. `libraryID`, `readerID`, `rootID` and `members` come from that verified snapshot. Member labels
   are historical display data, never identity or authority. IDs remain opaque and stable.
   `namespaces` and `operations.keys` must equal the requested set exactly, including an empty
   array for a verified namespace with no operations. The SDK rejects a different set.
3. Each namespace's `operations` is the **complete deterministic 0.1 replica order**, including
   held records as explicitly held evidence. Do not sort by claimed creation date, filter out
   no-ops/conflicts, deduplicate operation IDs, return only a recent page, or include operations
   from other namespaces. The array index is the admitted-order value passed to the importer.
   Refused, invalid-signature or unreadable envelopes are never admitted operations; retain
   their exact bytes and reasons through `unresolvedPaths`/`unresolved` instead.
4. Every `LegacyOperation` carries the verified operation ID, author ID/label, original
   kind/version, original decoded payload JSON and claimed-date JSON (including JSON `null`),
   admission (and `admissionDetail` for the original held reason), source path, and lowercase hex SHA-256 of the **exact authenticated signed body**.
   This digest is not a digest of the whole envelope or re-encoded JSON. Payload/date JSON can
   be reserialized without changing its values; preserve unknown fields and original wire
   dates/enums. The archive retains the exact envelope bytes for audit. `sourcePath` identifies
   those bytes in `records`. Do not translate old kinds or payloads in this record.
5. `records` contains exact immutable source bytes needed to audit the scope, including its
   authority and any untrusted envelopes. Record paths are stable relative source paths;
   entries under `requests/` may change, all other previously archived paths must remain
   present and byte-identical on catch-up. Every `unresolvedPaths` entry must exist in `records`
   and have an unresolved reason. Exclude authenticated out-of-scope operations. Never use an
   unverified namespace header to hide a bad signature: an envelope whose namespace cannot
   be trusted stays unresolved, even during a scoped migration. The reference adapter reads
   all envelopes to classify them, excludes verified foreign operations from its archive,
   and conservatively retains shared authority, requests and blobs. It does not need foreign
   namespace decryption keys or domain codecs. Shared authority/blob availability can still
   prevent a snapshot; namespace scoping is not an I/O or confidentiality boundary.
6. `evaluate(namespace:index:bindings:)` evaluates the actual old fold/service result for that
   entry **from the same snapshot**, using the prefix immediately before and including it,
   plus any whole-history receipt rules the old service requires. It must be deterministic
   for the snapshot and bindings and must not read live storage, write either library or
   launch workers. A valid signature and admission alone do not establish a successful old
   domain effect. Unknown codecs/outcomes must return `unresolved` with a reason in context.
7. `changeToken` changes whenever relevant source records, authority, admission or evaluated
   semantics change. It is an invalidation hint, not a clock, cursor or proof of completeness.
   `semanticFingerprint` is a stable per-entry token that changes when the old semantic result
   changes, including whole-history duplicate-ID receipts affected by a later arrival. It must
   not depend on destination bindings, timestamps of the migration run or fresh randomness.
   Version it when changing an adapter's evaluation rules. Do not set every entry's fingerprint
   to a whole-library digest: ordinary appends would then invalidate the imported prefix.

The SDK records the snapshot token but always obtains and compares the complete ordered scoped
prefix; it never skips verification because the token stayed the same. Prefix fingerprints bind
author, operation ID, signed-body digest, admission/detail, author label and semantic fingerprint.
Appends resume from the durable prefix. Missing/changed archived bytes fail closed. An earlier
insertion, deletion, admission change or changed semantic fingerprint publishes bounded
historical reconciliation evidence, keeps the barrier active and throws
`MigrationError.reconciliationRequired`. It never rewrites signed destination history.
The adapter is a trusted verification boundary; the SDK cannot independently verify signatures
from these flattened records. Test an app adapter against its actual legacy stack, including
revocation, stale edits, duplicate IDs, missing keys and late offline arrivals.

## Evaluation and context JSON

`LegacyEvaluation.outcome` uses the binding vocabulary below. A held record remains evidence
regardless of outcome. `contextJSON` is a UTF-8 JSON object using the exact domain importer
schema; unknown outcomes fail closed. Omission of a semantic fact is not proof of that fact.

| Namespace | Outcomes recognized by the binding | Context contract |
| --- | --- | --- |
| `reading.books` | The Rust books importer evaluates the old fold itself; reference sends `applied` for admitted records. | `{}`; the SDK preserves and binds the opaque books import state between units. |
| `reading.saved` | `applied`, `conflict`, `invalid`, `retained`, `noEffect`; otherwise unresolved | camelCase `ImportContext`: `identities`, `heads`, `existingItems`, `decoded`, `closureVerified`, `advancedReading`. |
| `listening.podcasts` | `applied`, `retained`, `conflict`, `noEffect`, `invalid`; otherwise unresolved | camelCase `ImportContext`: `reason`, `effectivePayload`, `identities`, `revisions`, `blobs`, `acceptedAnswer`, `emittedAnswers`, `catchUp`, `destinationHeads`. The binding supplies admission/disposition from the operation/outcome. |
| `notes` | `applied`, `conflict`, `lateEdit`, `invalid`, `noEffect`; otherwise unresolved | snake_case `ImportContext`: `identities`, `revisions`, `heads`, `effective_payload`, `alternatives`, `projected_alternatives`, `source_order`, `blobs`, `reviewer_kind`, `translated_inputs_current`. |

The exact field types and semantic requirements are documented on the Rust structs in
[saved/import.rs](../crates/colophon-core/src/domains/saved/import.rs),
[listening/import.rs](../crates/colophon-core/src/domains/listening/import.rs), and
[notes/import.rs](../crates/colophon-core/src/domains/notes/import.rs).
The [FFI mapping](../crates/colophon-ffi/src/migration.rs) is the vocabulary bridge.
In particular, full decoded saved content needs its original codec and validated closure;
blob descriptors alone never establish availability or verified source custody.

`LegacyImportBindings` supplies the SDK's persisted **imported** destination heads and revision
maps. Its dictionary keys are compact, unescaped-slash JSON arrays:

- `heads`: `[namespace, objectID, component]` → last imported output operation ID.
- `revisions`: `[namespace, component, oldOperationID]` → imported output operation ID.

Translate these into the domain's context keys (for example saved `item/component`, listening
`[component, objectID]`, notes `[category, oldRevision]`). Missing component heads may require
explicit JSON null, which differs from an absent field. Never refill these maps from current
native 0.2 edits: conditional catch-up must preserve those edits. The reference evaluator shows
working prefix/context construction and the SDK's `ImportBindings.swift` lists the components
it currently binds. Additional app codecs may need more component bindings; preserve unresolved
evidence until that support is implemented and tested.

## Persistence and completion

Each source unit is translated by the Rust importers and published as one root-signed
`colophon.importBatch` through the session's durable outbox. Permanent receipts bind stable
source/output keys, command digests and actual output IDs; restart after publication reuses the
receipt. Progress is encrypted in `migration-progress.aesgcm`; exact scoped source records live
in `source-archive/`, and any staged blob manifests in `blob-manifests/`. These are durable data.
`evidence()` reads synchronized, grant-checked engine evidence only for the selected namespaces.
Untrusted envelopes are evidence-only batches in the first sorted selected namespace, so a
books-only writer never needs a saved-reading grant to retain an invalid signature.

Only zero remaining operations **and** zero unresolved issues clear this scope's marker.
Unresolved issues are deliberately sticky pending reconciliation. `membersNeedingRejoin` is
informational; normal pairing, approval and grant checks remain required. The full source
library stays available to 0.1 apps, and later runs can catch up appended source history.

The reference integration tests are under `reference/swift/Tests/ColophonMigrationTests`.
They exercise real 0.1 signatures/folds, interruption/restart, native-edit conflicts, changed
prefixes, bad signatures, books-only migration from a mixed library, ignored foreign appends,
and a later notes upgrade into either a separate or explicitly identified shared destination.
Automatic earlier-prefix correction, full shipping-app codecs, large-library performance,
provider/hardware and real app lifecycle acceptance remain separate work.
