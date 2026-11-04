# Colophon 0.2

**Status: implemented preview, November 4, 2026.** The normative implementation is
`crates/colophon-core`; `conformance/0.2/` contains its reproducible library. This is a clean break
from [0.1](colophon-0.1.md), not an upgrade reader. MUST and SHOULD express protocol requirements.

## 1. What changes from 0.1, and why

| Change | Reason |
| --- | --- |
| One pure Rust evaluator, with explicit host signing and ECDH steps | The same admission and folds run on native and wasm; hardware keys need no synchronous callbacks. |
| P-256 signing and agreement; RFC 9180 HPKE instead of the bespoke key wrapper | One host-supported curve family and a standard encapsulation/key schedule. |
| `colophon/.../2` protocol markers and digest purposes; clean domain kinds | Remove app-specific constants and migration behavior. No 0.1 records or legacy kinds are interpreted. |
| Closed `device`, `app`, `agent`, `server` kinds | Authenticated member kind determines AI attribution. A server needs an explicit grant. |
| Closed grant fields: namespaces, access, expiry, write budget | Keep restriction semantics portable and fail closed on unknown restrictions. |
| Atomic revoke plus replacement epochs; atomic recovery plus historical shares and new epochs | A valid authority prefix cannot contain an uncompleted revocation or recover authority without recovering data. |
| Planned handover reshares first, then transfers and rotates all namespaces | Retain old data while removing the former root from future encryption. |
| Public operation admission metadata; grant-wide budget reservations | A reader can count signed writes across namespaces without holding every data key. Payloads and operation kinds remain encrypted. |
| Unknown kinds are admitted when authorized but skipped by domain folds | Preserve forward extensibility without accidentally interpreting new domain commands. |

The model is unchanged: a library has a root, recovery identity, invited members, scoped grants,
a signed authority history, encrypted operations and deterministic views. Revocation keeps
acknowledged operations. Unseen writes claiming pre-revocation authority are held, never folded.
No wall-clock timestamp decides conflict or display order.

## 2. Records and identity

An envelope is `{"body":"<base64>","signature":"<base64>"}`. Writers encode UTF-8 JSON with
object keys sorted recursively and slashes unescaped. Wire bytes use standard padded base64.
Readers MUST verify the exact decoded `body` bytes, without re-encoding them. The signature is
ECDSA P-256 with SHA-256, raw 64-byte `r || s`. No WebAuthn assertions, cosignatures or keyrings
are supported in this version.

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
`colophon/entropy/2`, info = eight-byte big-endian counter starting at zero, output length 32.
Take the first valid scalar for signing, then the next valid scalar for agreement. Invalid
scalars consume a counter and are skipped. A software recovery kit is 32 secret bytes: first
HKDF-SHA256 with salt `colophon/recovery/2`, info `identity`, length 32, then the identity
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
  `colophon/epoch/2\n<libraryID>\n<namespace>\n<epoch>\n<recipientID>`.

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

Hosts store immutable records and merge them as a set:

```
authority/00000001.json
requests/<memberID>.json
ops/<authorID>/<clock padded to at least 12 digits>-<operationID>.json
```

Exact duplicate records are harmless. A conflicting value at an existing path is an error;
this implementation also treats requests as immutable. A changed request uses a fresh identity.
Storage, transport, atomic persistence, conflict presentation and freshness are host concerns.
A merge validates the entire proposed authority chain before changing the replica.

Authority bodies contain `protocol:"colophon/authority/2"`, contiguous `seq` starting at one,
`previous` (SHA-256 of the exact preceding body, null only at genesis), `issued`, `by`, `kind`,
and these action fields:

| kind | Fields | Effect |
| --- | --- | --- |
| `genesis` | `label`, `ownerLabel`, `root`, `recovery`, `namespaces` | Initializes the library. Creation then introduces every initial epoch with `rekey`. |
| `rekey` | `epochs` | Introduces consecutive epochs with complete eligible recipient sets. |
| `grant` | `request`, `grant`, `shares` | Verifies the embedded self-signed request, admits the member and shares every historical epoch in scope. |
| `revoke` | `memberID`, `kept`, `epochs` | Ends the grant, preserves acknowledged operation IDs, and rotates every readable namespace in the same record. |
| `reshare` | `recipient`, `label`, `shares` | Shares all historical epochs before planned root transfer. |
| `handover` | `root`, `kept`, `epochs` | Requires a prior matching reshare of every epoch; ends the former root's access and rotates all namespaces. |
| `recover` | `root`, `label`, `kept`, `shares`, `epochs` | Recovery-signed atomic authority replacement, all historical data-key shares and rotation of all namespaces. |

`by:"root"` requires the current root's signature. Only `recover` uses `by:"recovery"`, signed
by the genesis recovery identity. Unknown actions or signers, chain gaps, invalid signatures,
and invalid recipient lists stop replay. Recovery rotation, stewards and delegated sub-grants
are deferred. Root replacements require a fresh identity; old roots retain their historical
member metadata and kept writes.

Requests contain `protocol:"colophon/request/2"`, `libraryID`, `member`, `label`, `kind`,
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
`purpose:"colophon/operation-id/2"`, `namespace`, `author`, `epoch`, `nonce` (an array of twelve
integer octets for this digest preimage), and `operation` (the complete plaintext with `id:""`).
This prevents an author replacing a kept operation's payload while reusing its ID.

The signed header body contains `protocol:"colophon/operation/2"`, `library`, `namespace`,
`author`, `epoch`, `id`, `clock`, `authority`, `created`, `nonce`, and `ciphertext`.
The first nine metadata fields, excluding `nonce` and `ciphertext`, are canonicalized as
AES-256-GCM associated data. `nonce` is 12 bytes and `ciphertext` includes the 16-byte tag.
The author signs the entire header. Plaintext ID, clock, authority and date MUST match the
header, and the content-derived ID MUST verify after opening. Kind and payload are encrypted.

**Order is `(clock, author, id)`, never `created`.** An honest writer increments the highest
non-refused clock it has seen in the namespace. Clocks must be positive and no greater than
JavaScript's exact integer limit, 2^53−1. Budget accounting uses the same order across namespaces.
Same-author duplicate operation IDs are refused to avoid equivocation.

After validating the header's signature, library binding, format and storage path, admission is:

1. Authority is newer than this replica: held, `authorityBehind`.
2. No grant/root authority at the cited sequence, or no write scope: refused, `notGranted`.
3. Epoch was not current at that sequence: refused, `wrongEpoch`.
4. Author's `created` is later than its grant expiry: refused, `expired`.
5. Author is revoked and ID is not in `kept`: refused, `revoked`, if citing revocation or later;
   otherwise held, `revokedBackdated`.
6. Earlier admitted signed headers have spent the write budget: refused, `budgetSpent`.
7. Otherwise the signed header is admitted and reserves one budget slot.

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

`DomainModule` supplies deterministic folds and operation/query specs containing a name,
description and JSON Schema. Known inputs are validated both by generated tools and when
folding received payloads. Unknown kinds are skipped; unknown payload fields survive edits.
An optional stale `expect` records a complete attributed alternative in `conflicts`. Edits
without `expect` apply in agreed order. All built-in queries currently expose only `read`.

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

Tools are `<namespace>__read` and `<namespace>__<kind>`, retaining namespace dots, for example
`reading.saved__capture` and `notes__addNote`. Tool lists are filtered by current grants,
expiry and budget; `call` independently enforces the same restrictions. Removing a tool from
a list is never the authorization mechanism.

The ledger is derived, not separately signed: authority events in chain order, verified requests
(including those embedded in grants) in member-ID order, then signed operations in agreed order, followed by malformed-record notices.
Its sequence is one-based display order. It reports creation, requests, grants, revocation,
rekeying, writes, held writes and refusals. Timestamps do not sort it.

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
