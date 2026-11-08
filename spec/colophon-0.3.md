# Colophon 0.3

**Status: implemented preview, November 7, 2026.** The normative implementation is
`crates/colophon-core`; `conformance/0.3/` contains its reproducible library. This is a clean break
from [0.1](colophon-0.1.md) and the successor of the unpublished 0.2 Rust core. Protocol and digest markers change to /3;
0.2 Rust wire records are not silently reinterpreted.
MUST and SHOULD express protocol requirements.

In LUFF's Marginalia repository, **"Colophon 0.2" names the Swift layout-2 step** whose design
this 0.3 specification absorbs: namespace-scoped operation paths, replaceable live playback
state, a root-signed `layout` authority entry, a verified-record cache and session readiness
states. That Swift document is not this repository's wire protocol.

## 1. What changes from 0.1, and why

| Change | Reason |
| --- | --- |
| One pure Rust evaluator, with explicit host signing and ECDH steps | The same admission and folds run on native and wasm; hardware keys need no synchronous callbacks. |
| P-256 signing and agreement; RFC 9180 HPKE instead of the bespoke key wrapper | One host-supported curve family and a standard encapsulation/key schedule. |
| `colophon/.../3` protocol markers and digest purposes; clean domain kinds | Remove app-specific constants and migration behavior. No 0.1 records or legacy kinds are interpreted. |
| Closed `device`, `app`, `agent`, `server` kinds | Authenticated member kind determines AI attribution. A server needs an explicit grant. |
| Closed grant fields: namespaces, access, expiry, write budget | Keep restriction semantics portable and fail closed on unknown restrictions. |
| Atomic revoke plus replacement epochs; atomic recovery plus historical shares and new epochs | A valid authority prefix cannot contain an uncompleted revocation or recover authority without recovering data. |
| Planned handover reshares first, then transfers and rotates all namespaces | Retain old data while removing the former root from future encryption. |
| Public operation admission metadata; grant-wide budget reservations | A reader can count signed writes across namespaces without holding every data key. Payloads and operation kinds remain encrypted. |
| Unknown kinds are admitted when authorized but skipped by domain folds | Preserve forward extensibility without accidentally interpreting new domain commands. |

The model is unchanged: a library has a root, recovery identity, invited members, scoped grants,
a signed authority history, encrypted operations and deterministic views. Revocation keeps
acknowledged operations. Unseen writes claiming pre-revocation authority are held, never folded.
No wall-clock timestamp decides conflict order. Ledger display uses claimed dates only within an authority sequence.

## 2. Records and identity

An envelope is `{"body":"<base64>","signature":"<base64>"}`. Writers encode UTF-8 JSON with
object keys sorted recursively and slashes unescaped. Wire bytes use standard padded base64.
Readers MUST verify the exact decoded `body` bytes, without re-encoding them. The signature is
ECDSA P-256 with SHA-256, raw 64-byte `r || s`. No WebAuthn assertions, cosignatures or keyrings
are supported in this version.

Canonical numbers follow the pinned serde_json 1.0.145 writer (Ryū binary64 formatting).
Integer tokens within signed/unsigned 64-bit range are encoded in decimal without leading
zeros (integer-token `-0` is parsed as floating negative zero). Out-of-range integer tokens,
fractional or exponent tokens are parsed as IEEE-754 binary64 with correct rounding
(`float_roundtrip`); writers use the shortest round-tripping decimal, with lowercase `e`, no
exponent leading zeros or positive sign, and `.0` for integral floats in fixed notation.
Negative floating zero is `-0.0`. Ryū's fixed/scientific notation choice is normative (for
example `1.0`, `1e-6`, `0.00001`, `6.713554789312184e-10`, `123456789.12345679`).
Integer and float representations remain distinct: `1` and `1.0` have different canonical
bytes. Non-finite numbers are forbidden. Hosts MUST retain binary64 values through JSON
serialization; readers MUST use correctly rounded parsing before recomputing operation IDs.

A public identity is `{"signing":"<base64>","agreement":"<base64>"}`: two valid, uncompressed
65-byte SEC1/X9.63 P-256 points. Key IDs are the first 32 lowercase hex characters of SHA-256
of the signing-key bytes. The library ID is the same truncation of the exact genesis body.

Dates accept UTC `YYYY-MM-DDTHH:mm:ssZ` or `YYYY-MM-DDTHH:mm:ss.sssZ`. The evaluator compares
validated calendar components, treating omitted milliseconds as zero. Other zones and leap
seconds are not supported. Dates describe author claims; signatures do not establish time.

All private-key work is two-phase. `begin_*` prepares exact signing bytes or an ECDH peer;
`finish_*` verifies a supplied signature or authenticates a key with the supplied raw shared
secret. The core holds no platform private keys. `SoftwareKeys` is an optional software
implementation for fixtures, native tools and recovery kits.

For deterministic software identities, expand a 32-byte seed using HKDF-SHA256 with salt
`colophon/entropy/3`, info = eight-byte big-endian counter starting at zero, output length 32.
Take the first valid scalar for signing, then the next valid scalar for agreement. Invalid
scalars consume a counter and are skipped. A software recovery kit is 32 secret bytes: first
HKDF-SHA256 with salt `colophon/recovery/3`, info `identity`, length 32, then the identity
procedure above. Recovery MUST be a separate identity from the root. Printed kit formatting
and custody/storage interfaces are host responsibilities.

## 3. Namespace encryption

Each declared namespace has consecutive epochs starting at one, each containing a fresh
256-bit AES key. An epoch is `{"namespace","epoch","seals":{recipientID: sealedKey}}`.
A sealed key is `{"enc":"<base64>","ciphertext":"<base64>"}` using
[RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) base mode:

- KEM `0x0010`: DHKEM(P-256, HKDF-SHA256).
- KDF `0x0001`: HKDF-SHA256.
- AEAD `0x0002`: AES-256-GCM; one message at sequence zero per encapsulation.
- HPKE `info` and AEAD associated data are the same UTF-8 string:
  `colophon/epoch/3\n<libraryID>\n<namespace>\n<epoch>\n<recipientID>`.

`enc` is the ephemeral uncompressed public key. Decapsulation obtains raw 32-byte P-256 ECDH
from the host, then performs RFC 9180 ExtractAndExpand and the base-mode key schedule in Rust.
Tests reproduce Appendix A.3's KEM, AES-128 key schedule, exporter secret and first ciphertext;
production uses the AES-256 suite identifier and key length.

Every fresh epoch MUST be sealed to exactly the current root, recovery identity, and active,
unexpired members with read access to that namespace. Revoked members are excluded. Writers
need read access because possession of an epoch key inherently enables decryption. Approval
shares every historical epoch in the approved scope, not just the current epoch.

Hosts supply a fresh, cryptographically random 32-byte seed per action. The core expands it
with the entropy procedure in §2 for epoch keys, ephemeral scalars and operation nonces. Fixed
or reused seeds are only appropriate for published fixtures. The core never invokes an OS RNG.

## 4. Storage and authority

Hosts store records and merge them as a set:

```
authority/00000001.json
requests/<memberID>.json
ops/<authorID>/<namespace>/<clock, 12 digits>-<operationID>.json
state/<authorID>/<namespace>/<slot>.json
history/<authorID>/<namespace>/<clock, 12 digits>-<operationID>.json
```

New immutable operations MUST use the four-part `ops/<author>/<namespace>/<clock>-<id>.json`
path. The signed header's author and namespace MUST match their path. Clients MUST list only
their requested namespaces, plus legacy three-part `ops/<author>/<clock>-<id>.json` records
whose namespace is unknown until the header is verified. A missing record in another known
namespace MUST NOT block this namespace. Missing legacy records remain conservatively unknown.
A replica selecting only part of a capped writer's grant cannot count that grant-wide budget.
It MUST refuse that writer's contributions with explicit `budgetScopeUnavailable` evidence, and
refuse local writes under that partial grant, rather than undercount unseen sibling operations.
Other writers remain readable. Select the complete grant scope, or issue single-namespace capped
grants, to evaluate those contributions. `Library::set_read_scope`, storage-engine options and
both SDK sessions enforce this rule.

`state/` is replaceable live playback state (see §5.1). `history/` is append-only engagement
evidence and MUST NOT participate in opening the library. Exact duplicate immutable records
are harmless. A conflicting value at an existing immutable path is an error; `state/` MAY be
replaced. This implementation also treats requests as immutable. A changed request uses a
fresh identity. Storage, transport, atomic persistence, conflict presentation and freshness
are host concerns. A merge validates the entire proposed authority chain before changing the
replica.

New libraries MUST write a root-signed `layout` authority entry with `layout: 2` after the
initial grants and namespace keys. Readers MUST reject an authenticated unsupported layout
(`layout` greater than this client supports, or an authenticated unknown authority kind)
before reading or writing content. Updated apps MUST show an explicit update-required session
phase, preserve the selected folder, identity, bookmark and bytes, and MUST NOT present an
empty library. Layout cannot be lowered.

Authority bodies contain `protocol:"colophon/authority/3"`, contiguous `seq` starting at one,
`previous` (SHA-256 of the exact preceding body, null only at genesis), `issued`, `by`, `kind`,
and these action fields:

| kind | Fields | Effect |
| --- | --- | --- |
| `genesis` | `label`, `ownerLabel`, `root`, `recovery`, `namespaces` | Initializes the library. Creation then introduces every initial epoch with `rekey`. |
| `rekey` | `epochs` | Introduces consecutive epochs with complete eligible recipient sets. |
| `grant` | `request`, `grant`, `shares` | Verifies the embedded self-signed request, admits the member and shares every historical epoch in scope. |
| `revoke` | `memberID`, `kept`, `epochs` | Ends the grant, preserves acknowledged signed-body digests, and rotates every readable namespace in the same record. |
| `reshare` | `recipient`, `label`, `shares` | Shares all historical epochs before planned root transfer. |
| `handover` | `root`, `kept`, `epochs` | Requires a prior matching reshare of every epoch; ends the former root's access and rotates all namespaces. |
| `recover` | `root`, `label`, `kept`, `shares`, `epochs` | Recovery-signed atomic authority replacement, all historical data-key shares and rotation of all namespaces. |
| `layout` | `layout` | Root-signed raise of the required storage layout. Never lowers it. Readers that cannot evaluate the authenticated layout MUST stop before content. |

`by:"root"` requires the current root's signature. Only `recover` uses `by:"recovery"`, signed
by the genesis recovery identity. Unknown actions or signers, chain gaps, invalid signatures,
and invalid recipient lists stop replay. Recovery rotation, stewards and delegated sub-grants
are deferred. Root replacements require a fresh identity; old roots retain their historical
member metadata and kept writes.

Requests contain `protocol:"colophon/request/3"`, `libraryID`, `member`, `label`, `kind`,
`namespaces`, `access`, `created`, and are signed by the requester. Both sides compute the pairing
code as the first four bytes of SHA-256(UTF-8 library ID || signing-key bytes), big-endian,
modulo 1,000,000, padded to six decimal digits. Hosts display the code before approval.

The approved grant is `{"namespaces":[...],"access":["read","write"],"expires"?,"writeBudget"?}`.
Read-only grants use `["read"]`. Namespace and access arrays MUST be nonempty; write implies
read. Namespaces use lowercase ASCII letters, digits, dots and underscores, at most 128 bytes.
The approved scope MUST be a subset of the request and the library's declared namespaces.
Unknown grant fields are rejected. `writeBudget` is a nonnegative integer, counted across all
of the member's namespaces. Zero permits no writes. The initial implementation admits one
immutable grant per identity; replacing or extending it requires a fresh identity.

## 5. Operations and admission

The plaintext is exactly the extensible payload model:

```json
{"id":"...","kind":"addNote","v":1,"clock":7,"authority":12,"created":"2026-11-04T12:00:00Z","payload":{}}
```

An operation ID binds its content: first 32 hex SHA-256 characters of canonical JSON containing
`purpose:"colophon/operation-id/3"`, `namespace`, `author`, `epoch`, `nonce` (an array of twelve
integer octets for this digest preimage), and `operation` (the complete plaintext with `id:""`).
The `kept` set contains full lowercase SHA-256 digests of the exact authenticated signed
header body bytes, not operation IDs or envelope/signature encodings. Revocation, handover and
recovery preserve only admitted records whose payload and content-derived ID authenticated.
A changed header cannot inherit preservation by copying an ID.

The signed header body contains `protocol:"colophon/operation/3"`, `library`, `namespace`,
`author`, `epoch`, `id`, `clock`, `authority`, `created`, `nonce`, and `ciphertext`. An
optional signed `live` stamp (`libraryID`, `slot`, `generation`, `operationID`) marks
replaceable playback state (§5.1). Generation is the namespace Lamport clock.
The first nine metadata fields, excluding `nonce` and `ciphertext`, are canonicalized as
AES-256-GCM associated data. `nonce` is 12 bytes and `ciphertext` includes the 16-byte tag.
The author signs the entire header, including `live` when present. Plaintext ID, clock, authority and date MUST match the
header, and the content-derived ID MUST verify after opening. Kind and payload are encrypted.

### 5.1 Live playback state and engagement evidence

Ordinary passive `listening.podcasts` `position` samples from an uncaveated current writer
MAY use replaceable live state:

```
state/<author>/listening.podcasts/<SHA-256 hex of the episode ID>.json
history/<author>/listening.podcasts/<clock, 12 digits>-<operationID>.json
```

Each state file is a normal signed operation with the additional `live` stamp. The decrypted
operation MUST match the stamp, slot and namespace. There is one current slot per episode per
author. Revoked or expired writers' live slots MUST NOT supply current state. Grants with an expiry or write budget MUST NOT publish live-stamped operations, including
retained copies under `ops/`; backdating does not remove these restrictions. Other historical
immutable admission is unchanged. Deliberate seeks (`seek: true`), completion, queue edits
and recovery MUST stay on the immutable `ops/` path.

Before an immutable action or a new live value relies on a replaceable revision, the exact
signed predecessor MUST be retained at its immutable operation path. Retention includes live heads
for the target episode and explicitly cited revisions, including nested completion references;
unrelated commands MUST NOT retain every live head in the namespace. A storage-backed writer MUST
fetch the exact predecessor envelope and match its verified digest before preparing that copy.
Missing or changed predecessor bytes fail the write. Every live write first
preserves its signed encrypted evidence under `history/`, then replaces its current slot.
Evidence alone MUST NOT become current state. History is available for audit and export.

A replacement that fails its expected-revision check MUST leave the previous admitted live
value in place. Signature, library/path/stamp binding, grant and expiry at the referenced authority,
and decrypted payload/slot binding MUST all verify before replacement. An unverified incoming date
MUST NOT invalidate an existing head. A locked replica MUST retain its old bytes until it can fully
verify the candidate. A candidate with an authenticated header but an unavailable epoch key MUST
be quarantined separately and retried after host unlock, including when authority and a new-epoch
replacement arrive in one batch. It MUST NOT evict the verified envelope or its high-water witness.
Malformed payloads discovered after unlock leave the verified fallback intact. Retained fallbacks
MUST be readmitted against current authority and the rebuilt durable clock; a revoked anchor cannot
continue to support a formerly admissible live generation. A storage engine MUST NOT persist a
verified checkpoint over a replacement awaiting an epoch key that this member can unlock.
This quarantine rule also applies to the first candidate for an empty slot. A candidate for an
epoch without a seal for this member is held as `unavailable`, not left in an unlock retry loop;
it MUST NOT replace the verified index or witness, and MUST NOT prevent a private checkpoint.
Future-authority candidates remain quarantined and are retried when that authority arrives.
A locked header loaded at open is not a verified high-water mark: lower candidates MUST remain
eligible until its payload is authenticated. Lower generations cannot replace an authenticated head; different exact envelope
bytes at the same slot/generation are explicit equivocation. An exact retained/live duplicate is folded once.

**Fold order is `(clock, author, id)`, never `created`.** A writer increments the highest
clock of an admitted, successfully authenticated operation in its namespace (zero if none).
Held, refused, unavailable and invalid-payload records MUST NOT advance the local write clock.
Live generations retain the signed clock encoding, but replaceable heads MUST NOT advance the
immutable admission clock or immutable namespace/author ordering tails. A local command advances
past relevant observed live heads only when continuing that slot or retaining its dependencies.
Clocks are positive integers at most 2^53−1. In sorted header order, an otherwise admissible
header MUST be no more than 1,024 above the highest earlier admitted header clock in its
namespace (initially zero); larger jumps are refused as `clockJump` without reserving budget.
This bound applies to live heads and retained live-stamped predecessors too. When a passive
sample reaches the durable prefix clock plus 1,024, the writer MUST publish that sample as
immutable intent and retain its targeted or explicitly cited live predecessors, including those
from other authors. When continuing a peer's older live head already at the 1,024 limit, its exact
retained `ops/` copy MUST precede admission of the new anchor. Subsequent live samples use the
resulting durable anchor.
Readers authenticate incoming immutable anchors before evaluating a live replacement in the same
batch. This periodic anchoring bounds live forward jumps without namespace exhaustion or losing
later deliberate writes. Standalone relay candidate authentication checks the absolute 2^53−1
limit, signature, authority, epoch, and payload bindings without requiring a local immutable prefix.
It does not itself admit the candidate: merge/ingestion MUST enforce the relative 1,024 bound after
receiving immutable anchors. Budget accounting uses the same order across namespaces.

An exact copy of a currently authenticated live head MAY be inserted into the durable projection
without re-verifying or reapplying the unrelated immutable prefix. This optimization requires exact
envelope and `(clock, author, id)` equality, unchanged episode ordering, and no outstanding admission
rejections or reducer conflicts/invalid outcomes that the insertion could change. Other earlier
arrivals retain normal ordered replay.
Retention MUST NOT decrease admission or local write clocks. Compatibility projection hashes MUST
continue to represent canonical durable order after insertion.
Only authenticated, admissible payloads compete for a same-author operation ID; the first in
fold order wins, and later authenticated competitors are refused as `duplicateID`. Invalid,
held or out-of-scope competitors never disqualify a valid or kept record. Signed header budget
reservations count distinct `(author, id)` pairs, so an invalid copy cannot consume an extra
slot ahead of its authentic record.

After validating the header's signature, library binding, format and storage path, admission is:

1. Check author membership, grant start, declared namespace and write scope using verified
   authority (the latest verified sequence for a future claim): refused, `notGranted`.
2. Author's `created` is later than its grant expiry: refused, `expired`.
3. Author is revoked and the signed-body digest is not in `kept`: refused, `revoked`, if citing revocation or later;
   otherwise held, `revokedBackdated`.
4. Authority is newer than this replica: held, `authorityBehind`. A future claim cannot bypass
   restrictions already established by the verified authority prefix.
5. Epoch was not current at that sequence: refused, `wrongEpoch`.
6. Clock exceeds the forward-jump bound: refused, `clockJump`.
7. Earlier admitted signed headers have spent the write budget: refused, `budgetSpent`.
8. Otherwise the signed header is admitted and reserves one budget slot per distinct author/ID pair.

A reader missing a historical key holds the corresponding content as `unavailable`. A present
key which cannot authenticate the ciphertext, plaintext metadata or content-derived ID yields
`invalidPayload` in the view's refused list. Such an otherwise admissible signed header still
reserves a budget slot: making a payload unreadable cannot conceal a write from other readers.
Member `writes` counts these admitted header reservations. Malformed unsigned/invalidly signed
records reserve nothing. Unknown payload versions are not folded. Domain-invalid payloads
remain admitted history but appear in the domain state's `invalid` IDs.

Current local actions also check host-supplied `now` against expiry and current revocation.
A namespace never granted reports `notGranted`; an ended former grant reports `revoked`.
The core cannot prove wall-clock dates or enforce a globally fresh budget from an incomplete
record set. New records can change admission; a strictly online budget needs a fresh sequencer.
Revocation cannot erase keys or content already obtained by a member.

## 6. Modules, views and tools

`DomainModule` supplies a display name, per-kind ledger phrases and operation/query specs containing a name,
description and JSON Schema. The Rust `Reducer` interface supplies serializable state, incremental
`apply` and named `query`; `DomainModule::fold` remains a compatibility replay wrapper.
Known inputs are validated both by generated tools and when folding received payloads. Unknown kinds are skipped. Each kind applies only its defined mutations: payload properties
outside that kind's schema are preserved in the projected object's `extensions` bag and
survive edits. They MUST NOT overwrite defined domain state or authenticated projection fields.
An input property named `extensions` is itself stored under `extensions.extensions`; it is
never flattened. `expect` and `seek` are command controls, not persisted object properties.
An optional stale `expect` records a complete attributed alternative in `conflicts`. Edits
without `expect` apply in agreed order. Built-in queries include compatibility `read`,
single-object lookups and bounded collection pages;
the additive local API and query names are documented in [the engine contract](../docs/engine.md).

| Namespace | Kind | Required payload | Optional defined fields |
| --- | --- | --- | --- |
| `reading.saved` | `capture` | `id`, `url` | `title` |
| | `setState` | `id`, `state` | `expect` |
| | `editMetadata` | `id` | `title`, `expect` |
| | `delete` | `id` | `expect` |
| `listening.podcasts` | `follow` | `id`, `url` | `title` |
| | `unfollow` | `id` | — |
| | `position` | `id`, `seconds` (nonnegative number) | `seek`, `expect` |
| | `queue` | `episodes` (ordered string IDs) | `expect` |
| | `episode` | `id` | `show`, `title`, `transcriptExcerpt` (text) |
| `notes` | `createNotebook` | `id`, `title` | — |
| | `addNote` | `id`, `notebook`, `text` | — |
| | `editNote` | `id`, `notebook`, `text` | `expect` |

Saved deletion is a tombstone; later edits remain conflicts. Podcast passive positions advance,
or apply if they saw the current position revision; a deliberate seek may move backwards.
Notes require an existing notebook and cannot move across notebooks through an edit.

States contain `items`; `shows`, `episodes`, `queue`; or `notebooks`, `notes`, respectively.
Every state also contains `conflicts` and `invalid`. Collection arrays use the agreed order of
their last applied revisions. A projected object's `revision`, `author`, `authorLabel`, `origin`
and `clock` are reserved authenticated fields. `origin` is `ai` iff the author's granted kind is
`agent`, otherwise `person`, regardless of payload claims. This is key attribution, not proof of
a physical person's involvement. OperationView still retains the original payload unchanged.

Tools are `<namespace>__<query>` and `<namespace>__<kind>`, retaining namespace dots, for example
`reading.saved__capture` and `notes__addNote`. Tool lists are filtered by current grants,
expiry and budget; `call` independently enforces the same restrictions. Removing a tool from
a list is never the authorization mechanism.

The ledger is derived, not separately signed. Authority entries retain chain order. Operations
citing authority N appear after entry N and before N+1, sorted within that group by normalized
`(created, author, id)`. This is display order only; folds and admission still use logical clocks.
A verified access request (including one embedded in a grant) appears immediately before its
grant. Pending requests appear after the latest verified authority's writes, sorted by normalized
`(created, memberID)`; future-authority operations follow in their cited sequence groups.
Malformed-record notices come last, ordered by author and ID. Sequence is one-based display
order and is recomputed after merging records. The ledger reports creation, requests, grants,
revocation, rekeying, writes, held writes and refusals. User-facing text uses module display
names (`listening`, `notes`, `reading`) and per-kind phrases such as “saved a link” and “added
a note”. Grant/request descriptions reflect the actual Cartesian-product access scope; this
version cannot grant read-only access in one namespace and write access in another to the same
identity. Standing facts use present tense. Revocation describes distinct preserved contributions
(edits to the same object do not inflate the count) and the fact that prior reading cannot be
undone. Each rotation action produces one combined namespace rekey summary. Initial epoch
lines are hidden because the creation entry explains that the namespaces are sealed with keys
only members hold. Write ledger entries expose optional `namespace`, `kind` and `origin`
(`person` or `ai`) for UI grouping. Namespace and origin come from verified headers and member
metadata; kind is included only when the encrypted payload authenticates. Other event types
omit these grouping fields. Payload-provided attribution cannot override them.

## 7. Host contract and boundaries

The [JavaScript contract](../docs/js-api.md) preserves `Library`, `WebCryptoKeys`, `Records`,
all original method names and outcome shapes. `merge` applies authority synchronously; `ready`
awaits asynchronous opening of new epoch keys. All other asynchronous operations open needed
keys automatically. `create` returns separate `recoveryKeys` unless supplied by the host;
those keys must be persisted independently. No plaintext keys are serialized into records.

No storage, network, clock, OS randomness, UI, relay, CLI executable, MCP transport or platform
keystore is implemented by the Rust core. Hosts provide these. The JavaScript host uses WebCrypto,
the host clock, and file/fetch loading of the wasm module. Native/wasm parity is tested from the
same fixture bytes. The Swift 0.1 implementation and vectors remain unchanged historical material.

### 7.1 Device-local verified-prefix optimization (no wire change)

An implementation MAY retain a device-authenticated cache of verified record membership,
admission evidence and reducer state. This is a local optimization, **not a new wire record**,
shared authority, portable backup, or replacement for signature/admission rules. A cache MUST
bind the format/reducer version, library, recipient, authority state, exact record paths and
digests, namespace admitted prefixes, and the corresponding reducer states. Namespace keys
shared with other members MUST NOT alone authorize a device-local verification cache.

The Rust `Engine` cache (`COLOENG5`, version 5; supersedes `COLOENG4`, reducer schema 8) uses a sorted path/digest index and per-namespace
rolling prefix hashes, authenticated together with a host-provided device-local 32-byte secret
(member-sealed). Index digests cover exact **outer envelope bytes** (including signatures) and
are independent of the provider content version; namespace prefix hashes cover admitted exact
**signed body** digests, as used by `kept`. The index retains these verified body digests so an
out-of-order retained predecessor can rebuild canonical prefix hashes without fetching historical
payloads. Podcast pagination and import-sidecar revisions bind to that canonical admitted prefix;
arrival-order rolling hashes MUST NOT leak into saved projections or cursors. A retained insertion
is permitted only when applying the predecessor itself produces no conflict or invalid outcome;
otherwise the implementation MUST replay in canonical order. Each index entry also binds the author's signing-key
digest, namespace epoch and referenced authority sequence. Restoration MUST compare the key
digest to verified authority and the authenticated epoch to the epoch at that sequence; lazy fetches
and audits also compare these bindings to the fetched header. `RecordSource.content_version` supplies a coherent opaque
provider token per path; a changed token triggers fresh signature/decryption/admission checks,
even if its bytes are identical. The cache binds the selected namespace list as well. Providers
without versions require scheduled digest audits and cannot claim immediate detection of an
unannounced in-place edit. The cache separately marks verified headers, payload-authenticated
IDs, projected operations, and rejected/observed bytes. Rejected records and unvalidated requests
MUST NOT become admitted merely by being indexed. Epoch secret keys are not persisted in the
cache. A storage-version, layout, reducer-schema, identity or library mismatch MUST cause
re-verification. Changing bytes at a previously verified **immutable** path is equivocation
and MUST fail closed. Replaceable `state/` paths MAY change only after complete verification and
monotonic generation checks. The engine checkpoint authenticates per-slot generation and exact
envelope-digest witnesses; these survive authority/order/projection invalidation. A lower generation,
same-generation different bytes, or invalid replacement fails closed and cannot be checkpointed as
new trusted evidence. An integrity audit requires exact indexed live bytes too; hosts refresh legitimate
replacements before auditing. A fresh replica without a witness cannot detect suppression of newer
valid state. Hosts protect the local cache
because reducer state can include plaintext. The Rust `checkpoint` module supplies a
member-signed HPKE key ticket and an AES-256-GCM encrypted checkpoint envelope, bound to the
exact library and member. Hosts use it (or equivalent protection) for persisted caches. Ticket
authentication precedes host ECDH; the member-sealed random key is separate from namespace keys.
Key inaccessibility must fail/retry, never generate a new identity. Native sessions persist these
protected caches. Authority changes MUST be authenticated and new available epoch keys unlocked
before the content replay pass; sessions MUST NOT replay history once before unlock and again after
unlock. Observed provider bytes are temporary staging, released after admission; later resets and
audits read the current coherent provider source. Pending unpublished journal bytes remain available
until persistence is acknowledged. Waiting-for-approval and denied sessions do not schedule an idle
checkpoint; an explicit checkpoint may record their held state without granting access. See [the engine format/API](../docs/engine.md#storage-backed-engine-stage-2).

SDK sessions distinguish first opening, waiting for download, ready, refreshing (usable
verified content from the same connection is retained) and retry. Results MUST be bound to the
exact session revision and connection. Query-backed content remains usable during waiting-for-download
and retry when the active connection retains a verified view. Grant-expiry refresh timers MUST accept
both UTC timestamp formats and wait until host `now` is strictly beyond the inclusive expiry. Pending data is never an empty library and never
enables absence-based writes. An authenticated unsupported layout surfaces `updateRequired`
without touching content bytes or identity.

Given an authenticated cache and a coherent current path listing, the core MAY trust covered
records without fetching, re-verifying, decrypting or JSON-parsing their historical operations.
It MUST fully verify, authenticate and admit new operations before applying them. It MUST check
access/expiry/revocation and current key availability for queries and writes, including after
cache restoration. A missing, stale, unknown-version, wrong-identity/library or unauthenticated
cache MUST fall back to full verification, never to an empty successful projection. Authority
listing additions, earlier arrivals that can affect admission, and changed
payload-key availability invalidate admission/projection evidence. A missing covered immutable path
is explicit unavailability, not permission to rebuild an empty namespace. This implementation rebuilds
fully on the invalidation events; a future implementation may safely use more precise explicit invalidation.

Path membership does not prove that the folder still holds the previously verified bytes. An
attacker who can rewrite the shared folder but cannot forge the local cache authentication can
suppress unseen records or replace/delete a covered record at its old path. A fast open can
continue displaying the earlier authenticated state until bytes are fetched. The attacker cannot
choose replacement reducer state or grant themselves authority through the cached path. Listing
a missing prefix path as absent makes the selected namespace unavailable; withholding an unseen suffix is not
observable. Neither this optimization nor ordinary signatures establish global freshness or
prevent rollback of a valid old local cache if local storage is also controlled by the attacker.

Hosts MUST have an explicit integrity-audit path. `Engine::verify_batch(limit)` lazily rechecks
up to `limit` indexed records, validating exact envelope digests and independently verifying
signatures on records previously classified as verified. History queries fetch/decrypt only
needed original operations and check their envelope digests on cache misses; plaintext caching
is bounded. Changed/missing covered bytes, or a trusted signature that fails audit, MUST produce
a clear integrity error. They MUST NOT silently substitute bytes, return empty content, or
silently rebase the trusted checkpoint. The Rust engine poisons subsequent query/write/cache
operations after such a failure, requiring host intervention and a fresh open. Hosts schedule
audits and surface their errors; the pure core does not run an autonomous background service.

Independent signature verification and payload authentication MAY execute in parallel. Hosts
MAY provide a trusted exact-byte P-256/SHA-256 batch verifier; it supplies cryptographic results
only. The core MUST still decide path binding, operation IDs, ordering, grants, epochs, budgets,
revocation and final admission. Native threading and provider choice do not alter wire semantics;
WASM remains single-threaded. Record storage and on-demand full-view allocations remain host-owned.

### 7.2 Authenticated import and blob extension (engine3)

The engine3 extension uses the existing signed/encrypted operation envelope and namespace epochs;
there is no new authority permission or public plaintext sidecar. Reducer generation 4 MUST
invalidate older projection caches; generation 5 (blob eager-download hints and claimed
creation/update dates in listening notes and notes) likewise invalidates generation 4 caches.
Generation 6 added immutable playback ordering barriers. Generation 7 enforces bounded live
anchoring and rejects caveated live stamps; all older projection caches MUST be invalidated. Reducers receive kind, immutable grant and root role from
verified authority, never from payload or historical source assertions.

`colophon.importBatch` is a root-only engine operation carrying a bounded source-unit key,
evidence, ordered clean children, historical alternatives, occurrence reservations and blob
manifests. A source unit MUST become visible through one complete admitted publication. Readers
MUST validate its structure/reservations before applying any child and MUST retain immutable
source receipts so equivalent retries cannot repeat effects. Changed content under an accepted
key MUST fail. The signed parent authenticates virtual children and their deterministic output
revisions; children are not separately signed envelopes. All ordinary admission, revocation,
epoch and domain conditional-write rules still apply. Original attribution remains labelled
historical evidence, never replacement authenticated authorship. Only this authenticated root
publication can confer imported-baseline semantics.

Evidence and historical alternatives MUST be encrypted in their destination namespace and read
only after current grant/expiry/revocation/key checks. The common bounded queries and the exact
batch/revision encodings are defined in [engine3's engine contract](../docs/engine.md#engine3-authenticated-import-storage-and-blobs).
Rejected old writes MUST NOT enter effective domain state through the overlay. Earlier-source
reconciliation is additive: retain previous/current evaluated outcomes and imported component
heads as alternatives, preserving native edits and immutable signed destination history.
Acknowledging historical alternatives requires an authenticated app/device, the observed revision
and the exact alternative set; changing native state requires a clean command with domain checks.

Blob descriptors name complete plaintext SHA-256, size and media type. Signed encrypted manifests
bind independently authenticated, content-addressed ciphertext chunks, their namespace epoch,
order and plaintext identities. Hosts persist chunks before publishing manifests, synchronize them
as retained user data, and provide bounded lazy reads. Readers MUST check current namespace access,
ciphertext address, AEAD authentication and chunk identity before returning bytes, and MUST verify
the complete descriptor before marking the full original verified. Missing, inaccessible and invalid
bytes MUST remain distinct from available content. Reference counts are idempotent live-reference
counts, not an erasure promise or permission to discard retained immutable evidence.

Any namespace writer MAY publish an ordinary `colophon.blobPublish` `{manifest,reference,required?}`
and adjust references with `colophon.blobReference` `{digest,reference,retain,required?}`.
`required` (boolean) is a synchronized eager-download hint: clients SHOULD fetch every chunk of a
required blob once its manifest is admitted, and MAY fetch others lazily on first read. The
common grant-checked query `blobs({after?,limit?≤1000,required?})` pages published manifests
in digest order as `{digest,size,mediaType,chunks,references,required}` without chunk metadata;
`blob({digest})` additionally reports `required`. A client MAY remove its local copy of a chunk
only when another holder is confirmed (a relay receipt or another member's live reference) or
when the owner explicitly asks to discard the sole copy. Chunks no manifest names MAY be
removed after a grace period only under the same confirmed-custody or explicit-discard rule. Local removal never deletes relay copies; the relay has no blob GC.

Earlier 0.3 clients that lack this extension skip these unknown engine operations and cannot render their imported
children. All participating apps MUST upgrade before enabling this extension. No 0.1 signature,
codec, grant or historical agent authority is imported into the 0.3 trust chain.

## 8. HTTP exchange

Clients publishing authority history MUST await acknowledgement of each authority sequence before
uploading its successor. Sorting a concurrent upload batch is insufficient: observers may otherwise
see an authority gap and fail closed. Independent immutable content uploads may remain parallel.

This section defines how hosts move records between devices through an untrusted relay. It
revises the 0.1 HTTP profile (§5.3 of 0.1) with an incremental change feed. The relay is a
storage and transport service only: it never grants access, never holds namespace keys and
cannot make a record admissible. Every pulled record is verified, admitted and decrypted by the
receiving core exactly as if it had been read from a local folder (§4, §5).

### 8.1 Libraries, paths and credentials

A relay serves one or more **library slots**. `{base}` is the slot URL, for example
`https://relay.example/v1/libraries/home`. A slot name is 1–64 bytes of lowercase ASCII
letters, digits, `.`, `_` or `-`, starting with a letter or digit. A slot is named by the
host, not by the library ID, because a device that is joining does not know the ID yet. A slot
SHOULD hold a single library; clients MUST check it (§8.4).

Record paths are exactly the §4 layout (`authority/<8 digits>.json`, `requests/<memberID>.json`,
`ops/<authorID>/<namespace>/<clock>-<operationID>.json`, legacy three-part `ops/`,
`state/<authorID>/<namespace>/<slot>.json`, `history/<authorID>/<namespace>/<clock>-<id>.json`)
plus encrypted blob chunks `blobs/<64 lowercase hex>` (§7.2). Components MUST NOT be empty, `.`,
`..`, start with `.`, or contain `\` or NUL; a path is shorter than 512 bytes. Relays MUST
reject other paths with 400.

Requests MAY carry `Authorization: Bearer <token>`. A relay that requires a token MUST compare
it in constant time and answer 401 with `WWW-Authenticate: Bearer` for a missing, wrong or
unknown-slot token (an unknown slot is indistinguishable from a wrong token). **A token grants
storage access to one slot and nothing in the library**: it is not membership, cannot approve
a request and is never sent to or interpreted by the core. Production relays MUST be reached
over TLS (directly, or through a TLS-terminating proxy or a private network such as Tailscale).

### 8.2 Endpoints

| Request | Responses |
| --- | --- |
| `GET {base}` | 200 `{"protocol":"colophon/relay/3","slot","limits":{"recordBytes","blobBytes","pageEntries","waitSeconds"}}` |
| `GET {base}/changes?after={cursor}&limit={n}&wait={s}&namespace={ns}` | 200 change page; 410 if the cursor can no longer be honored. Repeat `namespace` to include several; omitted means every namespace. Authority, requests and legacy three-part ops are always included. |
| `GET {base}/records/{path}` | 200 exact bytes with `ETag: "<sha256 hex>"`; 404 |
| `PUT {base}/records/{path}` with `If-None-Match: *` | 201 created; 200 identical bytes already present; 412 different bytes present |
| `PUT {base}/records/state/{…}` with `If-Match: "<prior sha256>"` | 200 replaced; 412 if the current bytes differ or no slot exists. Creation uses `If-None-Match: *`. |
| `PUT {base}/records/requests/{name}` without `If-None-Match` | 200 replaced or 201 created (only under `requests/`) |
| `DELETE {base}/records/requests/{name}` | 204 (only under `requests/`; absent is also 204) |

A change page is `{"entries":[{"path","size","sha256"}],"cursor":"<opaque>","more":bool}`.
Entries appear in the order the relay accepted them; `sha256` is the full lowercase digest of
the stored bytes. `after` omitted (or empty) lists from the beginning. The returned cursor is
passed back as `after` to receive only later entries; `more:true` means another page is
immediately available. `limit` defaults to 500 and is clamped to the relay's `pageEntries`.
With `wait` (0–30 seconds) and no entries after the cursor, the relay MAY hold the response
until an entry arrives or the wait elapses, then answers with whatever it has (possibly an empty
page and the same cursor). Cursors are opaque, slot-bound and only valid on the relay that issued
them. A relay that lost its log, was restored from backup or compacted it MUST answer 410 for
cursors it cannot continue; the client then lists again from the beginning. A path appears again
after a `requests/` or `state/` replacement with the new digest; a deleted request is listed with
`"deleted":true` and no digest.

`PUT` bodies are the exact record bytes (`Content-Type: application/octet-stream`; relays ignore
the type) with a `Content-Length`. An immutable `PUT` requires `If-None-Match: *`. A live-slot
replacement requires `If-Match` naming the exact bytes the client verified; an unconditional
`state/` PUT is 428. Re-sending identical bytes is idempotent and answers 200, so a client can retry any upload
after a lost response. A `PUT` of different bytes to an existing immutable path is 412 and MUST
NOT change the stored bytes. A blob chunk's name MUST equal the SHA-256 of its bytes; a relay
MUST reject a mismatch with 400. `requests/` alone supports unconditional replacement and
deletion, for parity with the 0.1 profile and a person withdrawing a pending request. 0.3 SDK clients still treat requests as
immutable (§4): they never replace or delete one, and they report a changed request as a
conflict instead of overwriting their local copy.

Live promotion MUST validate signature, current authority/grant, expiry/revocation, signed generation,
operation ID and decrypted slot binding. Compare generations only after verification. Upload/download
referenced immutable predecessors and append-only history first, then CAS the exact old live bytes.
Keep a newer local head on a race; re-list and retry instead of overwriting it. Namespace selection
is part of a client's persisted cursor identity. A relay does not perform these semantic checks.

### 8.3 Limits and errors

A relay MUST bound request size and SHOULD publish its limits at `GET {base}`. The defaults are
16 MiB per record, 65,552 bytes per blob chunk (64 KiB plus the AEAD tag), 1,000 entries per page
and a 30-second wait. Oversized bodies are 413, without storing a prefix. A relay MAY enforce a
per-slot quota (507) and rate limits (429 or 503 with `Retry-After`). Writes MUST be atomic per
record (no reader observes a partial file) and durable before 200 or 201. Publication is per
record, not across a batch, matching §4.

A relay MAY validate records (path grammar, blob digests, envelope shape, even signatures and the
authority chain) and refuse ones it cannot accept with 400 or 422. It MUST NOT alter, re-encode,
reorder fields of, or synthesize records, and MUST return exactly the stored bytes. A relay sees
paths, sizes, digests, timing, the requesting address and token, the plaintext authority history
and requests (member public keys, labels, kinds and grants), and the public operation metadata of
§5 (namespace, author, epoch, clock, authority sequence and claimed date). It never sees namespace
keys, operation kinds or payloads, or blob plaintext.

### 8.4 Client synchronization

Immutable intent/evidence uses set reconciliation; live slots use verified conditional replacement.
A client keeps its local store as the source of truth and repeatedly:

1. **Lists** `changes` from its saved cursor until `more` is false, adding each entry to its
   remembered remote set. On 410 it forgets the cursor and remote set and lists from the start.
2. **Checks the library.** If both sides hold `authority/00000001.json` and the digests differ, the
   slot holds a different library: the client MUST stop and report an error, pulling and pushing
   nothing. Clients fetch and authenticate authority before any content, rejecting an unsupported
   layout even on their first relay-backed opening.
3. **Pulls** each listed immutable path the local store lacks, verifies its SHA-256 against the listing,
   and appends the bytes to the local store (which rejects conflicts), then hands the new records
   to the core as an external change. A listed path whose digest differs from the local record is
   a conflict; the local bytes are kept and the conflict is reported.
4. **Pushes** each local immutable record the remote set lacks with `PUT … If-None-Match: *`. 200 and 201
   both mean the relay now holds the record; 412 is a conflict, reported, never overwritten.
5. **Blob chunks** (`blobs/<sha256>`) are pushed before the records of the same pass, so a peer
   never admits a manifest whose ciphertext the relay lacks. They are never pulled as part of the
   record set: a client fetches a chunk when a read needs it, or eagerly for blobs marked
   `required`, and MUST check that the bytes hash to the chunk's name before storing them. Chunks
   are verified again (AEAD, chunk digest, whole-content digest) by the core on read. A missing
   chunk is reported as missing, never as empty content.

A client SHOULD keep the work of a pass proportional to the change: persist the cursor and the
remembered remote set (for example as an append-only log), enumerate local paths without reading
record bodies, and read only records it must push or compare.

Absence from a relay MUST NOT be read as deletion, and an unreachable, unauthorized or reset relay
MUST NOT be read as an empty library: a client whose local store is empty MUST complete a
successful listing before reporting that no library exists or creating one in that slot. Clients
SHOULD retry transport failures with capped exponential backoff and jitter, honoring
`Retry-After`, and SHOULD surface their state (idle, syncing, offline, unauthorized, error).
Relay order, timing and listings carry no authority: admission, revocation and fold order are
decided only by the core from signed records (§5). A relay can withhold or delay records (a
freshness attack); it cannot forge, alter or reorder their meaning.
