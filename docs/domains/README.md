# Domain port specifications

Proposed, 2026-11-06. These documents extend, rather than describe implemented parity in,
[Colophon 0.3](../../spec/colophon-0.3.md). Read the [migration plan](../app-migration.md)
first. No Rust code or production library was changed or examined for this inventory.

The source baseline is Marginalia commit `3503057517a0e14e2f21325403fa1bc3a23e487c`.
All Marginalia paths below are relative to that repository and were read with `git show
HEAD:<path>`, with paths discovered using `git ls-tree`. They refer to committed code,
not the concurrent working tree. Source code establishes possible persisted shapes; it does
not establish which shapes occur in a particular person's library. No private library data
is reproduced here. Heat labels are static call-path assessments, not measurements.

| Specification | 0.1 kinds covered | Proposed clean kinds | Named queries | Estimated reducer/index Rust LOC |
| --- | ---: | ---: | ---: | ---: |
| [Books](reading.books.md) | 9 | 10 | 8 | 700–1,100 |
| [Podcasts](listening.podcasts.md) | 29 advertised + 4 service-only | 30 | 17 | 3,000–5,000 |
| [Saved reading](reading.saved.md) | 36 | 24 | 19 | 5,000–8,000 |
| [Notes](notes.md) | 12 | 13 | 10 | 1,200–2,000 |

Counts exclude common diagnostics and import evidence, and include every named query in each
domain table. Estimates cover validation, reducers and maintained query indexes, not crypto,
host I/O, extraction/rendering, importer codecs, FFI or tests. They are planning ranges, not
benchmarks. Reading's source/annotation/history graphs and listening's service projections
dominate the work. The five-kind podcast and three-kind notes preview are not app parity.

## Shared proposed contract

**Types.** `ID`, `Rev`, `Text`, `URL` are strings; `Digest` is 64 lowercase hex characters;
`Int` is an interoperable integer (absolute value at most 2^53−1); `Number` is finite binary64;
`Bool` is boolean; `JSON` is arbitrary finite JSON. `T?` means optional/nullable only where
the row permits it; `T[]` is an array and `{K:T}` a map. Dates in new payloads use the 0.3 UTC
instant grammar. Calendar days use validated Gregorian `YYYY-MM-DD` and never shift zones.
Legacy Swift `Date` wire encoding must be decoded by its codec, not guessed from its type.
Import preserves the original date representation in evidence; claimed dates never arbitrate
new state. UTF-16 locations stay UTF-16, with boundaries validated against the pinned source.
In compact command tables, unannotated IDs/references are strings, titles/names/text/reasons
are Text, and a referenced capitalized model uses its definition in that document. A group
such as `title,creator:Text?` applies the type to both fields. Query arguments `cursor?` and
`limit?` always mean Cursor and Int. `Instant` and `Day` mean the timestamp/calendar types above.
`Attributed` means the object's scalar domain fields plus `{id:ID,revision:Rev,author:ID,
authorLabel:Text,origin:Text,clock:Int}`; it excludes child collections, blobs' bytes and
conflict arrays. `AttributedCandidate` adds `{component:Text,candidate:JSON,expected:Rev?,
found:Rev?,historical:Bool}`. Historical attribution is a separately labelled provenance
record, never a replacement for the authenticated fields. Query `touched` is the last
effective mutation's fold-order key; display `updated` dates are labelled claimed instants.

**Identity.** New user-created objects use lowercase UUIDs. IDs are opaque to reducers;
legacy identifiers are not rejected solely for not being UUIDs. Commands reject empty IDs,
control characters and IDs over 1,024 UTF-8 bytes (smaller domain limits take precedence).
An ID is scoped by library, namespace and object category; it is not an operation ID. Import
uses a persisted identity map keyed by source library/category/ID, preserving the original ID
when unambiguous. Collision or an old remove/recreate lifecycle gets a deterministic new ID
derived from the framed source tuple and creation operation digest. Cross-references use that
map, never titles or guessed URLs. Podcast feed/GUID identities retain their exact old input
bytes; URL normalization must not silently rename existing objects.

**Ordering and revisions.** Only admitted, authenticated operations enter a reducer, in
`(clock, author, id)` order. Unknown kinds/versions are retained and skipped; invalid known
payloads are retained with an invalid diagnostic. No wall-clock conflict resolution. A query
revision identifies the admitted prefix, not elapsed time. Object `revision` is the last
effective mutation; component heads (position, metadata, plan, queue, text) are separate where
specified. `expect` absent means ordered unconditional mutation; `expect:null` explicitly
expects no head; `expect:Rev` compares that component. A stale mutation adds a complete
attributed alternative and does not advance the target head. Resolving alternatives requires
the current head and the exact sorted set of conflict revisions observed; a stale resolution
is itself an alternative. Graph kinds instead name parent revisions and retain all branches.

**Unknown fields.** Preserve unknown payload properties under the target object's `extensions`
bag, merging by key only on effective mutations. An input property literally named
`extensions` is retained as `extensions.extensions`, never flattened. Unknown nested model
fields have a bag on that nested object. Conflict versions retain their own bags. Controls
(`expect`, `seek`, expected-head sets) are not object properties. Reserved attribution fields
cannot be overwritten by a payload or its extras. Unknown fields on commands without an
object belong to their receipt/evidence record. Byte-sensitive imported structures retain the
original bytes as well as parsed fields; re-encoding through a lossy Swift model is not preservation.

**Attribution.** `revision`, `author`, `authorLabel`, `origin`, `clock` derive from authenticated
0.3 metadata. `origin=ai` iff the authenticated member kind is `agent`. Book-author text is
`creator`, to avoid collision with signer `author`. Legacy payload `origin`, original authors,
publisher assertions and accepted-by claims remain explicitly historical claims. App/device
role fences in 0.1 map to `app|device`; legacy `service` is not silently upgraded to `server`.
The new root signs imported operations as importer, never as the former author.

**Deletion.** Hard delete creates a permanent tombstone for that occurrence, retaining its
last value, source references and conflicts. No same-ID resurrection; copy/restore-as-new
allocates a new ID and records its source. Later edits become alternatives attached to the
tombstone. Archive/unfollow/hidden are reversible state, not deletion. Parent deletion hides
children in ordinary queries but retains their history. Deletion never promises removal of
old encrypted bytes or revocation of a reader's previously acquired content.

**Queries and bounds.** Each query returns `{revision, value}` or a typed outcome
`notFound|deleted|notGranted|unavailable|invalidArgument|staleCursor`. These must not collapse
to an empty library. A page is `{rows:T[], next:Cursor?, total:Int}`; default limit 50, maximum
100 unless specified. Cursor binds namespace, query, normalized arguments, sort key and
revision. A changed prefix yields `staleCursor`, so the host restarts the page rather than
silently duplicating/skipping rows. Sorts have ID tie-breakers and a specified deterministic
core collation (Unicode scalar ordering; locale presentation can be host-local). Query responses
cap at 1 MiB; previews truncate explicitly with `truncated` and a single-object/blob retrieval
path. Lists never embed every note, cell, transcript, alternative or source version.

Maintain ID, parent, status, tag, source, ordered-list, count and conflict indexes incrementally.
Pages should cost `O(log n + page size)` after index lookup, single objects `O(log n)`, cached
counts `O(1)`; content search can use a separate local index. Cross-namespace source pointers
do not confer read permission. Whole-state export is a background streaming operation, never
a UI query. Widget publishers request bounded snapshots on namespace change; widget renders
read device-local files. Player ticks and scroll frames use already loaded values.

**Blobs.** Proposed `Blob = {digest:Digest, size:Int, mediaType:Text}` names plaintext bytes;
`Source = {id:ID, original:Blob?, metadata:Blob?, ...}` pins immutable evidence. Encryption,
ciphertext location, epoch/key delivery and byte availability belong to the host blob adapter;
the core does no I/O. A manifest is not proof the bytes are present or an anchor is valid.
Host resolution returns `available|missing|inaccessible|invalid` and verifies digest, length,
format and anchor boundaries. Search/extraction caches, downloads, file bookmarks, credentials,
playback engines, drafts, scroll geometry and pending outboxes remain device-local. Do not
drop retained user originals merely because a cache also holds a copy. Blob encryption/storage
is a proposed extension requiring coordination with the core worker; 0.3 §7 does not specify it.

## Import contract used by every mapping table

The root's existing Swift reader verifies a copied 0.1 library and evaluates its actual folds
and typed service projections. Import preserves history, not just the visible snapshot. Each
source operation gets a manifest entry keyed by `(sourceLibrary, namespace, authorID,
operationID, signedBodyDigest)`, with old author label, kind/version, old order, claimed date,
admission status, domain outcome, exact-body digest algorithm/purpose and output operation IDs.
Use SHA-256 of the exact authenticated signed operation body for `signedBodyDigest`; separately
label any canonical plaintext or referenced legacy-journal digest. Never confuse an old ID,
plaintext digest and signed-body digest. Retain exact source envelopes in the read-only source
archive. The manifest and any evidence blobs are encrypted user data in the destination,
not public fixtures. One-to-many outputs additionally carry a stable child index and
`importSource` provenance in their payload (an extension property, not authenticated old authorship).

Translate effective changes to clean commands. Rebase old expectations through **component**
head maps; several output commands may correspond to one old operation. Carry old conflicts,
invalid attempts, losing candidates and unknown kinds in an immutable import evidence stream,
queryable through common `importEvidence(sourceLibrary?, namespace, object?, cursor, limit)`.
This common stream is an importer/host sidecar, not a legacy opcode in the Rust domain reducer.
Normal domain conflict queries can expose its attributed alternatives through the SDK, with
`historical:true`. Never replay a formerly stale operation without its expectation and thereby
make it effective. Sidecar durability and access must be part of migration completion.

For stricter new validation, preserve the original in evidence and report the unprojectable
field/operation; do not silently clamp, invent an anchor or certify a missing blob. Existing
out-of-range values can be displayed as historical evidence until repaired by a clean command.
Unknown optional fields survive in extensions; a required unknown semantic discriminant stays
evidence-only. Missing keys, invalid signatures, held/refused records and unreadable payloads
cannot become trusted domain effects. Record them as unresolved migration entries and retain
the old archive. No claimed source author/role can grant new capabilities.

Catch-up is idempotent by the full source tuple and transform version, never just the highest
clock. Re-evaluate the complete source admission and affected fold prefix when new records
arrive; compare prior effects. Late old writes become normal conditional commands against
the last imported component heads. Native 0.3 changes win over imported baselines; changed
source outcomes or conflicts require explicit alternatives/reconciliation, not deletion or
rewriting of signed destination history. Don't automatically rerun jobs, revive grants,
activate browser presence or re-enroll agents. Migration is complete only when every source
record and required blob has a durable disposition; unresolved entries remain visible.

## Port acceptance work

Use synthetic payloads for vectors: each kind, boundary validation, stale edits, ties, duplicate
IDs, reverse delivery, unknown fields, deletion and imported alternatives. Compare the old
Swift projection with normalized new queries and the evidence manifest. Test incrementally,
full replay and checkpoint replay from an invalidated earlier prefix. Include 100k-operation
libraries and real-shaped large queues, notebooks and annotation graphs; measure the targets
in the migration guide. No examples in this change contain personal data. The handoff records
remaining proof gaps; these specifications are not a claim that those gates have passed.

## Engine3 integration status

The shared evidence/blob proposals above now have an implemented engine extension; see the
[engine3 contract](../engine.md#engine3-authenticated-import-storage-and-blobs). Schema 4 supplies
authenticated kind/grant/root context, atomic encrypted import publications, bounded evidence and
historical-alternative queries, deterministic occurrence reservations, additive prefix comparison,
and lazy encrypted blob chunks with live reference counts. Historical conflict UI must join the
separate labelled overlay; acknowledging it does not itself change native domain content. Hosts
still verify old folds, source formats and anchors, preserve exact archives, apply typed collision
maps, synchronize blob chunks, and provide user-facing correction workflows. These are explicit
boundaries, not evidence that all shipping-app codecs or production data have been accepted.
