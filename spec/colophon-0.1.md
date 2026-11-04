# Colophon 0.1

**Status: 0.1, adopted October 11, 2026.** This is the protocol baseline. Later sections record
additive domain extensions. Reference implementation: the Swift package in this repository.
Conformance vectors: [`conformance/`](../conformance).

The key words MUST, SHOULD and MAY are used as in RFC 2119.

## 1. Model

A **library** is a person's or an organization's data, identified by its first authority record. It
has a **root** that decides who may do what, a **recovery identity** that can replace the root, and
any number of **members**: devices, apps, web clients, agents and services. Each member holds its
own keys and a **grant** to some **namespaces**. Content is a set of signed, encrypted **operations**
per namespace. Every client folds the operations it can read, in one agreed order, into the same
state. Storage only ever holds signed records and ciphertext.

Layers, each a separate module in the reference implementation, usable alone:

| Layer | Module | Needs |
| --- | --- | --- |
| Records, identities, sealing, recovery | `ColophonCore` | — |
| Storage and transport | `ColophonStore` | Core |
| Authority history and admission of members | `ColophonAuthority` | Core, Store |
| Operations, admission, domain modules | `ColophonReplica` | Core, Store, Authority |
| Domains: `reading.saved`, `reading.books`, `listening.podcasts`, `notes` | one module each | Replica |
| MCP adapter | `ColophonMCP` | Replica |

A verifier needs only Core and Authority. A relay needs nothing: it stores bytes.

## 2. Records

Every record is UTF-8 JSON, written with object keys sorted, slashes unescaped, dates as ISO 8601
(`2026-10-11T09:30:00Z`) and byte strings as standard base64 with padding.

A **signed record** is `{"body": <base64>, "signature": <base64>, "assertion"?, "cosignatures"?: [...]}`.
`body` is the exact bytes of the inner JSON. `signature` is ECDSA P-256 with SHA-256 over those bytes,
encoded as raw `r || s` (64 bytes; WebCrypto's and IEEE P1363's format), except a WebAuthn controller
(§6.6), whose signature is ASN.1 DER. Readers MUST verify the stored bytes and MUST NOT re-encode
before verifying. `assertion`, when present, is `{"authenticatorData", "clientData"}`: the WebAuthn
authenticator data and the exact clientDataJSON bytes. It is omitted when absent, so a record without
one keeps its bytes. `cosignatures` is a list of `{"signer", "signature", "assertion"?}` over the same
body, used for quorum handovers (§6.3) and for keyring changes (§6.6).

Digests are lowercase hex SHA-256. An **ID** derived from a key is the first 32 hex characters of
the digest of that key's bytes.

## 3. Identities

An identity has two P-256 keys: one for signing, one for key agreement. Its public form is
`{"signing": <X9.63 uncompressed, 65 bytes>, "agreement": <same>}` (WebCrypto `raw`). Its ID is the
ID of `signing`.

Where private keys live is the implementer's choice, declared as **custody**:

| Custody | Meaning |
| --- | --- |
| `hardware` | Non-extractable hardware: Secure Enclave, TPM, StrongBox. |
| `platform` | Non-extractable but not dedicated hardware: a browser `CryptoKey` with `extractable: false`. |
| `software` | Bytes in memory or a file: agents, servers, tests. |
| `custodial` | Held by a service for a client that can't hold keys (§7.3). |

Apple clients SHOULD keep member keys in the Secure Enclave, and the root's keys in the Secure
Enclave requiring the person's presence for every use. Passkeys are not identities in this standard;
they MAY be used for website sign-in and as an additional recovery factor.

### 3.3 Recovery kit

A recovery kit is 32 random bytes, printed as Crockford-style base32 (alphabet
`ABCDEFGHJKMNPQRSTVWXYZ0123456789`, most significant bit first, final partial group zero-padded) in
groups of four separated by `-`. Parsers MUST ignore case, spaces and `-`.

The **recovery identity** is derived from the kit. For purpose `signing` and then `agreement`, the
private scalar is HKDF-SHA256(IKM = kit bytes, salt = UTF-8 `colophon/recovery/1`,
info = UTF-8 `<purpose>/<counter>`, 32 bytes) for the first counter from 0 whose output is a valid
P-256 scalar (non-zero and below the group order). The public half is named in genesis.

## 4. Namespace keys

Each namespace has a sequence of **epochs**, each with a random 256-bit AES key. A key is given to a
principal as a **sealed key** `{"ephemeral", "box"}`: generate an ephemeral P-256 key pair; ECDH
with the recipient's agreement key; derive a 32-byte wrapping key with HKDF-SHA256(salt = recipient's
signing key bytes, info = UTF-8 `colophon/sealed-key/1`); AES-256-GCM-seal the key; `box` is
`nonce (12) || ciphertext || tag (16)`; `ephemeral` is the ephemeral public key, X9.63.

Every epoch key MUST be sealed to the current root and the recovery identity, and to every steward
(§6.3), in addition to the members granted that namespace. A library that has adopted a keyring (§6.6)
seals each new epoch to the vault and to the members granted that namespace, and not to the root, the
recovery identity or the stewards.

## 5. Storage

### 5.1 Layout

```
authority/00000001.json          authority entries, numbered from 1, 8 digits
requests/<member ID>.json        enrollment requests
ops/<member ID>/<clock 12 digits>-<operation ID>.json
```

Records are immutable once written, except requests, which their requester MAY replace. Creating a
record MUST fail if the path exists. A store SHOULD present not-yet-downloaded cloud files (for
example iCloud's `.<name>.icloud`) as absent and request their download.

### 5.2 Local-first sync

Clients MUST read and write a local store. Transports copy records between the local store and a
remote one: authority entries forward from whichever side is ahead; operation files by name in both
directions, never overwriting; requests, with the requester's copy winning. Transports never decrypt.

### 5.3 HTTP profile

- `GET {base}/{directory}/` → 200 and a JSON array of names, or 404.
- `GET {base}/{path}` → 200 and the bytes, or 404.
- `PUT {base}/{path}` with `If-None-Match: *` → 201, or 412 if it exists.
- `PUT {base}/{path}` without it → 200 or 201; only under `requests/`.

A relay MAY require a bearer token for storage access; it grants nothing in the library. A relay MAY
refuse records it can't verify against the authority history (a validating relay), and MUST NOT
alter records.

## 6. Authority history

Entry `n` is a signed record whose body is:

```json
{"seq": n, "previous": "<digest of entry n-1's body>", "issued": "<date>", "kind": "...", "by": "root", ...}
```

`previous` is absent only for genesis. Verifiers MUST check numbering, `previous` and the signature
of every entry in order, and MUST stop at the first failure.

| `kind` | Fields | Effect |
| --- | --- | --- |
| `genesis` | `label`, `root`, `recovery`, `controller`?, `stewards`?, `threshold`? | Entry 1. The library ID is the first 32 hex characters of the digest of genesis's body. |
| `grant` | `member`, `label`, `role`, `custody`, `namespaces`, `write`, `expires`?, `caveats`?, `keyOperator`? | Admits a member, or adds a new grant to an active member. |
| `revoke` | `memberID`, `kept` | Ends the member's grants from this entry on. |
| `shareKey` | `memberID`, `namespace`, `epoch`, `key` | Gives a principal one epoch key. The first `shareKey` for an epoch introduces it. |
| `handover` | `root` | Replaces the root. |
| `stewards` | `stewards`, `threshold` | Replaces the steward quorum. |
| `rotateRecovery` | `recovery` | Replaces the recovery identity. Signed by the root. |
| `keyring` | `controllers`, `threshold`, `vault`, `slots`, `signer`?, `recoverThreshold`? | Replaces the controller keyring. The first one, signed by the root, adopts it (§6.6). |

`role` is one of `device`, `app`, `web`, `agent`, `service`. `controller` is a string map naming who
the library belongs to, for example a contracting legal entity.

### 6.1 Signers

`by` is `root`, `recovery` or `quorum`. The current root signs every entry. The recovery identity
MAY sign only a `handover`. A `quorum` handover MUST carry valid signatures, in `signature` and
`cosignatures`, from at least `threshold` distinct stewards. After the first accepted `keyring`
entry, this section no longer applies: later entries are signed by controllers (§6.6).

### 6.2 Revocation

A `revoke` MUST be followed by a new epoch for every namespace the member held, sealed to the root,
the recovery identity, stewards and remaining members. `kept` lists the revoked member's operation
IDs the holder had already seen; they remain admitted.

### 6.3 Handover and recovery

A planned handover writes `shareKey` entries for every epoch to the new root **before** the
`handover`. A recovery writes the `handover` signed by the recovery identity, then `shareKey`
entries signed by the new root. A quorum handover writes the steward-signed `handover`, then the new
root re-shares keys obtained from a steward.

### 6.3.1 Rotating the recovery identity

A `rotateRecovery` writes `shareKey` entries giving every existing epoch to the new recovery
identity, then the `rotateRecovery`, then a new epoch for every namespace sealed to the root, the
new recovery identity, stewards and the members that hold it. From that entry on, only the new
recovery identity may sign a recovery `handover`. The old kit can still open the epochs it held.

### 6.4 Grants and caveats

A member's grants form a history; the grant in force at entry `n` is the latest with `seq <= n`.
Caveats restrict a grant within a namespace:

| `kind` | Fields | Rule |
| --- | --- | --- |
| `kinds` | `kinds` | Only these operation kinds. |
| `ceiling` | `field`, `max` | That integer payload field ≤ `max` in each operation. |
| `budget` | `field`, `max` | Sum of that field over the member's admitted operations, in agreed order, ≤ `max`. |

Amounts are integers in minor units (for money, cents). An admitting replica MUST refuse an
operation under a caveat kind it doesn't recognise. `budget` is evaluated over what the replica can
see; a verifier that must enforce a budget strictly needs a complete, fresh view (§12).

### 6.5 Entries from a newer version

A verifier that meets an entry `kind`, `by`, `role` or `custody` value it doesn't know MUST stop
there and report that the library needs a newer client, not that it is damaged. It MUST NOT skip
the entry or fold the history around it.

Unknown fields are ignored, so a later version MUST NOT add a field to an existing kind that makes
a grant narrower. Restrictions go in a caveat (refused when unknown, §6.4) or in a new kind
(refused when unknown, above). A controller `kind` or role, a slot `kind`, or a combined-slot part
`kind` that this version does not know is the same kind of stop (§6.6).

### 6.6 Keyring (0.2)

A library MAY adopt a keyring of controllers in place of the single root. The first `keyring` entry
is the upgrade. It MUST be `by: root`, MUST verify with the current root, and MUST NOT carry an
`assertion` or any cosignature. It carries the complete new state and replaces any previous keyring.
The library ID does not change. Before that entry, an entry `by: controller` is a bad signature.

After the upgrade, `genesis`, `handover`, `stewards` and `rotateRecovery` break the chain, and `by`
of `root`, `recovery` or `quorum` is a bad signature. `root` and `recovery` keep their last public
keys and MUST NOT authorize later entries. Every later entry is `by: controller`, and `signer` names
a current controller.

| Field | Rule |
| --- | --- |
| `controllers` | The complete list. Each controller's ID is the ID of its `key`. |
| `threshold` | How many distinct `control` controllers MUST sign a keyring change. At least 1, and at most the number of controllers with `control`. When `recoverThreshold` is greater than 1, `threshold` MUST be at least `recoverThreshold`, and at least `threshold` controllers MUST have `control`, so one key cannot change the ring. |
| `recoverThreshold` | How many distinct `recover` controllers a recovery change needs. Absent means 1, and writers MUST omit it when the value is 1. When present, at least 2 and at most the number of controllers with `recover`. |
| `vault` | Public identity of the vault. New epoch keys are sealed to this ID (§4). |
| `slots` | Every way to open the 32-byte vault seed. |
| `signer` | Controller ID of the primary signature. Required when `by` is `controller`. |

A controller:

| Field | Rule |
| --- | --- |
| `kind` | `p256` or `webauthn`. Anything else needs a newer client. |
| `key` | P-256 signing key, X9.63 uncompressed, 65 bytes, a valid point. |
| `rpID` | Relying party ID. Required for `webauthn`. `id.luff.works` is an example, not a fixed value. |
| `credential` | WebAuthn credential ID, so a client can ask the authenticator. Verifiers ignore it. |
| `label` | A name for people. |
| `roles` | Each is `approve`, `control` or `recover`. An unknown role needs a newer client. |
| `verification` | When true, every WebAuthn signature from this controller MUST have the UV flag. |

A slot `kind` is `sealed`, `prf` or `combined`. Anything else needs a newer client. A slot this
version understands but cannot open breaks the chain.

| `kind` | What opens the seed |
| --- | --- |
| `sealed` | `recipient` and `sealed`. The seed is a sealed key (§4) to that recipient. |
| `prf` | `credential`, a 32-byte `salt` (also the PRF input), and `box`. `box` is AES-256-GCM of the seed. The key is HKDF-SHA256(IKM = the PRF output, salt = `salt`, info = UTF-8 `colophon/vault-prf/1`, 32 bytes). |
| `combined` | `parts` (at least two) and `box`. Each part yields a 32-byte secret. The box key is HKDF-SHA256(IKM = those secrets concatenated in `parts` order, salt = empty, info = UTF-8 `colophon/vault-combined/1`, 32 bytes). Opening needs every part. |

A part `kind` is `prf` or `sealed`. A `prf` part stores `credential` and a 32-byte `salt`; its secret
is HKDF-SHA256(IKM = the PRF output, salt = `salt`, info = UTF-8 `colophon/vault-part/1`, 32 bytes).
A `sealed` part stores `recipient` and `sealed`; its secret is 32 random bytes in a sealed key.
Anything else needs a newer client.

`p256` signs raw `r || s` over the body and MUST NOT include an assertion. `webauthn` MUST include
an assertion. Its signature is ASN.1 DER ECDSA over `authenticatorData || SHA-256(clientData)`.
An implementation whose ECDSA check hashes its input MUST pass that concatenation, not a second
hash. A WebAuthn signature MUST pass every check below.

1. `clientData` is JSON. `type` is `webauthn.get`. `challenge` is base64url, without padding, of
   SHA-256(body). `origin` is `https://<rpID>` or `https://<labels>.<rpID>`: no user info, port,
   path or empty label. `crossOrigin` is absent or false. Other members are ignored.
2. `authenticatorData` is at least 37 bytes. Bytes 0..<32 are SHA-256 of the UTF-8 `rpID`. In the
   flags byte, UP (0x01) is required. UV (0x04) is required when the operation demands verification
   or the controller's `verification` is true. The sign counter is ignored.

Every signature on the entry MUST verify, primary and cosignatures. Signers MUST be distinct current
controllers. A controller with both `control` and `recover` counts for both.

| Entry | Who may sign |
| --- | --- |
| `grant`, `revoke` | One signature, from a controller with `approve`. |
| `shareKey` | One signature, from a controller with `approve`, or with `control` when the recipient is the vault or a member already granted that namespace (vault rotation). |
| `keyring`, control path | At least the current `threshold` distinct `control` controllers. WebAuthn signatures require UV. If the new `recoverThreshold` is lower than the current one, the same entry also needs at least the current `recoverThreshold` distinct `recover` controllers. One key MUST NOT be able to lower it. When `recoverThreshold` is greater than 1, `threshold` is at least that high, so one key also MUST NOT add a controller or replace slots. |
| `keyring`, recovery path | Every signer has `recover`, and there are at least the current `recoverThreshold` of them. WebAuthn signatures require UV. The change only adds. |

Recovery only adds when every current controller is present and equal as a whole record, both
thresholds are unchanged, the vault is unchanged, and every current slot is still present. Slots MAY
be reordered. Recovery MAY add a controller and its slot. It MUST NOT remove, demote, replace a slot
or lower `recoverThreshold`. An added controller MAY have `control` only when the current
`recoverThreshold` is at least the current `threshold`. Otherwise an added controller MAY hold only
`approve`. In Standard both thresholds are 1, so a recovered device is as powerful as the owner. The
recovery notice tells the person and cannot win a race against someone who already removed them.

The upgrade shares every existing epoch to the vault, then writes the `keyring` entry, both signed
by the root while the library is still in §6.1. Epochs that already exist stay sealed to whoever
held them. Epochs created after the upgrade are sealed to the vault and to current members of that
namespace, and not to the root, the recovery identity or the stewards. A later `keyring` change that
replaces the vault opens every existing epoch with the current vault and, in the same batch, shares
each of those epochs to the new vault, then starts a fresh epoch of every namespace sealed to the
new vault and to current members of that namespace. Without the current vault that change is refused.

A `sealed` or `prf` slot can open the vault alone. A `combined` slot cannot. A library that wants
two recovery keys to be required uses one combined slot for each pair, so no single recovery key
opens the vault. An approver's device slot MAY stay a single-key slot.

## 7. Enrollment

### 7.1 Requests

A requester writes `requests/<its ID>.json`, a record signed by itself whose body is
`{"member", "label", "role", "custody", "namespaces", "keyOperator"?, "write"?, "created"}`. `write`
says whether the requester wants to write. Absent means an older client. The holder MUST verify the
signature before showing the request.

On a keyring library, one approval grants exactly the requested namespaces and `write` (false when
`write` is absent) and shares every epoch of those namespaces. A namespace that has no epoch yet gets
epoch 1, sealed to the vault, to the new member, and to members who already hold that namespace.

### 7.2 Pairing code

Both sides show six digits: the first four bytes of SHA-256(UTF-8 library ID || requester's signing
key bytes) read as a big-endian unsigned integer, modulo 1,000,000, zero-padded. The person approves
only if the codes match.

### 7.3 Custodial members

A client that can't hold keys — such as a remote MCP client authenticated by OAuth — MAY be
represented by a member whose key a service holds. Its grant MUST say `custody: custodial` and name
the `keyOperator`. Each such client SHOULD be its own member, so the root can see and revoke each
one. Interfaces MUST show that the operator can act as that member.

## 8. Operations

### 8.1 Format

An operation's plaintext is:

```json
{"id": "...", "kind": "...", "v": 1, "clock": 7, "authority": 12, "created": "<date>", "payload": {...}}
```

`clock` is one more than the largest clock the author has seen in the namespace. `authority` is the
newest authority entry the author had verified. `created` is the author's own clock; it MUST NOT be
used for ordering or authorization except as stated in §8.3.

It is stored as a signed record by its author whose body is the header
`{"author", "namespace", "epoch", "sealed"}`, where `sealed` is the plaintext AES-256-GCM-sealed with
the epoch key (`nonce || ciphertext || tag`). An author writes only under `ops/<its own ID>/`.

### 8.2 Order

Admitted operations are ordered by (`clock`, author ID, operation ID), compared as integers then
byte-wise strings. Every client folds in this order.

### 8.3 Admission

For each readable operation, in order:

1. If `authority` is newer than the verifier's latest entry: **held** (the verifier is behind).
2. No grant in force at `authority`: **refused**.
3. Grant lacks `write` or the namespace: **refused**.
4. `epoch` isn't the epoch current at `authority`: **refused**.
5. `created` after the grant's `expires`: **refused** (binds honest writers only).
6. Author revoked and the operation not in `kept`: **refused** if `authority` ≥ the revocation,
   otherwise **held** — it may be honest offline work or a backdated forgery, and only a person can
   decide.
7. A caveat fails: **refused**.
8. Otherwise **admitted**.

Held operations MUST NOT be folded. Clients SHOULD show them for review.

### 8.4 Blobs

Large content (transcripts, attachments) is stored as a blob: the bytes AES-256-GCM-sealed with a
namespace epoch key, written to `blobs/<digest>` where `digest` is the SHA-256 of the sealed bytes.
An operation references it as `{"digest", "plain", "epoch", "size"}`, where `plain` is the SHA-256
of the plaintext. The signed operation is the authority; a reader MUST check both digests. Blobs
are immutable and synced like operations.

## 9. Domain modules

A domain module names a namespace, a version, operation kinds, and a deterministic fold from
admitted operations to state. Folds MUST skip kinds they don't know and MUST keep payload fields they
don't interpret. Conflicts are recorded, never silently resolved: a write carrying `expect` that
doesn't match the current revision is recorded as a conflict or kept as an alternative, as the
module specifies.

### 9.1 Modules in 0.1

- `reading.saved` — `capture.link`, `item.setState`. Saved links, consumption and retention.
- `reading.books` — `book.add`, `book.edit`, `book.remove`, `book.setPlan`, `book.progress`,
  `note.add`, `note.edit`, `note.resolve`, `note.delete`. Rereads append a reading; concurrent note
  edits keep alternatives until `note.resolve` settles them. Clients may add `coverID`, `year`,
  `pages` and `openLibraryKey` (Open Library) to `book.add`.
- `listening.podcasts` — `show.follow`, `show.unfollow`, `show.settings`, `episode.setState`,
  `episode.position`, `queue.set`, `note.add`, `note.edit`, `note.resolve`, `note.delete`,
  `episode.segments`, `episode.transcript`, `episode.chapters`, `playlist.save`. Notes carry `origin` (`person` or `ai`) so derived
  text is never mistaken for the person's words. Segments are recorded per audio file, because
  dynamic ad insertion changes timings: `audio` is the lowercase hex SHA-256 of the retained audio
  bytes, never the address that served them. A client MUST NOT skip by segments recorded under any
  other key, and SHOULD NOT record a person's review for audio it can't hash (a stream). A person's
  review beats detection for the same audio.
  Transcripts are blobs (`{"text", "words"?}`); a timed transcript beats an untimed one, then a
  person's or publisher's beat on-device or agent ones. A transcript made from audio carries that
  recording's digest in `audio`, so its times are trusted only on those bytes. Chapters for an
  episode without the publisher's are recorded per recording (`episode.chapters`, `audio` the
  digest, `source` `generated` or `person`; a person's beat generated ones). Episode ID: first 32 hex characters of the digest of
  `<feed URL>\n<GUID>`. A deliberate seek always applies; passive progress applies if its writer saw
  the current position or it moves forward.
  A playlist is saved whole: `manual` lists episodes in order; `automatic` draws them from `shows`
  (or all followed shows) in `newest`, `oldest` or `byShow` order, minus `excluded`. An automatic
  playlist may also narrow by `progress` (`any`, `unplayed`, `inProgress`), `maxMinutes` and
  `titleContains`, keep `included` episodes whatever the rule says, and put episodes from `pinned`
  shows first, in that order. All of these are optional. A client that saves a playlist should
  carry over fields it doesn't understand. Clients work out an automatic playlist's episodes from the feeds. Archiving hides a playlist reversibly; a
  save whose `expect` is stale is kept beside the current version, never replacing it.
- `notes` — `notebook.create`, `notebook.rename`, `notebook.archive`, `cell.put`, `cell.move`,
  `cell.delete`, `cell.output`, `cell.resolve` (settles concurrent versions). A deleted cell stays
  deleted: a later `cell.put` for it is kept aside as an edit to a deleted cell, never re-created. Cells are `markdown`, `latex`, `code` or `raw`. Outputs carry the
  digest of the source that produced them.

  Additive v1 Notes foundation (Scribenda): `entry.put`, `attachment.add`, `entry.propose`,
  `proposal.review`. Existing operation encodings and the four cell kinds are unchanged.
  `cell.put` may carry an `entry`; omission on later edits preserves membership. Entry and cell
  IDs belong to one notebook; a foreign-notebook command MUST NOT change them. Cells without
  an entry remain ordinary notebook contents; no migration is inferred. Older clients skip the
  new operation kinds and continue rendering text cells, without entry grouping or materials.

  `entry.put` carries `entry`, `notebook`, optional `title` and calendar `date` (`YYYY-MM-DD`),
  `tags` and an optional `expect`. A matching expected metadata revision replaces the current
  metadata; a missing/stale expectation for an existing entry retains the complete alternative,
  including authenticated signer, label and operation revision. An ordinary edit does not erase
  alternatives. Entries are general containers for sessions, journal days or research captures,
  not separate type-specific stores.

  `attachment.add` carries an immutable `attachment` ID, `notebook`, optional `entry`, `role`
  (`reading`, `slides`, `handout`, `image`, `audio`, `file`, `link`), `name`, optional `mime`, and
  exactly one of `blob` or `source`. Blobs use §8.4 and retain exact imported bytes; a missing local
  blob is pending content, not an absent attachment. `source.kind=web` carries an HTTP(S) `url`
  bookmark, not retained evidence. `source.kind=library` carries `library`, `namespace`, `artifact`
  and exact `revision`, with optional descriptive `quote`, zero-based PDF `page`, `seconds` and
  `recording` digest. A timed source requires a recording digest. A source resolver must still
  verify location and authority: a reference is neither proof of a quote nor an access grant.
  Reusing an immutable attachment or proposal ID with changed payload or signer is invalid;
  exact same-signer replay preserves the first revision without another projected object.

  `entry.propose` appends a contribution with immutable `proposal` ID, `notebook`, `entry`,
  optional proposed `title`, `tags`, organised `markdown`, and `inputs` mapping every current
  entry cell ID to its exact revision. All inputs must match and have no unresolved alternatives.
  This input map binds captured text cells only; attachment revisions and external source
  evidence are not checked by this foundation and MUST NOT be presented as verified inputs.
  Producer identity comes from the admitted operation, never a claimed origin field.
  `proposal.review` carries `proposal`, `notebook`, `keep` and optional person-edited `markdown`.
  App/device/web principals may keep or dismiss; agent/service principals may not review.
  Keeping requires the complete input set still to match. First review wins; exact same-reviewer
  replay is harmless. A kept contribution is appended attributed organised text, with original
  proposal, edited contribution and reviewer revision preserved separately. It never rewrites
  source cells, ink, attachments or entry metadata. App signatures establish app authorship,
  not independent proof of a physical human gesture. Review and source resolution are distinct.

  Implementations validate nested content when folding even if a writer bypasses adapter
  schemas. The Swift projection lists invalid operation IDs without deleting their signed
  records. `notes__entry` reads bounded entry collections (default 20, maximum 50 per collection,
  at most 1 MiB response), with explicit source-text truncation. Generated MCP operations expose
  the same content vocabulary; this does not establish a deployed Notes relay transport,
  item-level decryption, export/recovery acceptance or automatic cross-namespace access.

### 9.2 Operation specs

Modules SHOULD publish each operation's fields (name, type, required, allowed values). Adapters
generate their surfaces — MCP tools, App Intents, CLIs, HTTP endpoints — from these, and validate
against them before writing.

### 9.3 Queries

Modules MAY publish read-only queries — a name, fields and a function over what the member can
see (for example `transcript`, which includes timed sentence `segments` when the transcript is
timed, `search_transcripts`, `moment` — what was said around a second, its chapter and nearby
notes — and `chapters`). Adapters expose them beside operations,
so agents ask the same questions an app's own features do.

## 10. Adapters

An adapter acts as exactly one member. An MCP server over a replica exposes `library__status`, a
`<namespace>__read` tool per module, and a tool per operation named `<namespace>__<kind>` with dots
replaced by underscores. Every write goes through the replica, so admission, caveats and attribution
apply unchanged.

## 11. Conformance

`conformance/` holds a library written by the reference implementation, the
private keys used (`keys.json`), and `expected.json`: the library ID, the recovery identity derived
from the kit, member IDs, the pairing code, the verified authority summary, and for three members the
admitted, held, rejected and unreadable operations and the folded shelf. An implementation conforms
to 0.1 if it reproduces `expected.json` from the records and keys.

## 12. Freshness and privacy

- A verifier MAY cache the authority head for ordinary reads and reversible writes. It MUST read
  the latest authority entries before admitting an operation with external effect — spending,
  publishing, sending — or a caveated budget.
- Storage and relays see sizes, timing, member IDs and namespace names. Namespace names SHOULD NOT
  carry personal information.
- A namespace shared with a service member is readable by that service. Interfaces MUST say so.
- Revocation stops future access. It can't make a member forget what it already decrypted.

## 13. Open questions

- Compaction and checkpoints for long histories.
- An online sequencer profile alongside peer ordering.
- Moving re-shared keys between steward devices during a quorum handover.
- Capability negotiation when a newer module version writes kinds an older client doesn't know.
