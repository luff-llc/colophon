# Colophon 0.5

**Status: final candidate, revision 5, for review, 2026-11-12.** Not frozen, not
implemented, not released, and no version number has been changed anywhere. Revision 2
answered two reviews of revision 1 (152d991); revision 3 answered two reviews of revision 2
(9e90470); revision 4 replaced every recovery special case with one mechanism, pending
transitions with veto (§8.7); revision 5 answers two reviews of revision 4 (4032d44) by finishing
that mechanism's state model. The mappings are in [colophon-0.5-changes.md](colophon-0.5-changes.md) §G. It becomes normative only under §21.
The work to implement it is [colophon-0.5-implementation.md](colophon-0.5-implementation.md).

**What it replaces.** This document is complete for every identity, authority, grant, call,
head and record-header format it names. It replaces [colophon-0.4.md](colophon-0.4.md),
[colophon-0.4-keys.md](colophon-0.4-keys.md) and every part of
[colophon-0.3.md](colophon-0.3.md) that those kept, except the engine and host mechanics that
§11.8 incorporates by exact section and substitution. Nothing else in an older document is
normative for 0.5. The Swift keyring format that the shipped apps write is specified in §16.3
so that every binding can verify a predecessor.

MUST, MUST NOT, SHOULD and MAY are requirements on a conforming reader or writer.

## 0. What an account is

- **An account is a keyring.** A person, a company or a project is an account. Its identifier
  is the digest of its first authority record, so it means the same thing everywhere, before
  any server has heard of it, and it outlives every key, device, server and app.
- **Controllers hold authority.** A controller is a passkey, a security key, a device owner key
  or a recovery kit, with roles. How many are needed for each kind of change is a setting of
  the keyring, with a default and a range (§18).
- **Members do the work.** Apps, devices, agents and servers are members with **grants**: a
  signed, scoped, expiring permission from the account to a key. A key that has ever been a
  member of an account can never be its controller, and the reverse (§3.3).
- **One key may serve many accounts**, and anyone who sees two histories can tell that the same
  key controls both (§3.3). One person may hold many keys. The format knows no "work" or
  "personal" identity.
- **Data belongs to the owner.** Records are encrypted to the account's vault and to members
  that may read. Nothing in the format binds an account to a server, a deployment or a web
  origin, except the relying-party ID that WebAuthn attaches to each passkey (§3.2, §4.3).
- **Short sessions speak for members.** A member can pass part of its grant to a short-lived
  key through a signed **link**, and that key signs **calls** to services (§12). Sessions never
  appear in the account's history and never author records.
- **Homes keep and vouch for copies.** A home is a member appointed to keep the account's
  history and sign **heads**. One home is primary and orders new entries (§13).

**Words.** 0.4's *library* is an *account*; "library" remains the word apps may show. New
words: *terms*, *link*, *call*, *home*, *primary home*, *head*, *receipt*, *policy*,
*holder*, *upgrade*, *predecessor*, *successor*.

## 1. Results

| Result | Meaning |
| --- | --- |
| `ok` | Accepted. |
| `malformed` | The bytes or structure break a rule here. |
| `badSignature` | A required signature, assertion, possession proof, threshold or key binding failed. |
| `newerFormat` | Authenticated content of a known protocol that this reader doesn't know. The reader stops and asks to be updated. |
| `unavailable` | Something needed (history, a fresh head, a receipt, an epoch key, a record) could not be obtained. Never evidence that the thing is absent, valid or invalid. |
| `refused:<reason>` | Well-formed and authentic, but not permitted. |
| *held* | Not yet decidable; kept and retried (records, §11.5; future-dated or unreceipted entries, §8.5). |

**The verification pipeline is normative everywhere:** bounded generic parse; bind the account
and the claimed signer; verify every signature, possession proof, threshold and key binding;
check authorization; only then interpret unknown fields, kinds or values. Unknown content that
is not yet authenticated never yields `newerFormat`. An unknown **protocol marker** is never
authenticated content: it names an object type this reader can't verify and is `malformed`. A
failure at an earlier step always wins.

## 2. Encoding and parsing

### 2.1 Canonical JSON

Every signed body is the UTF-8 encoding of one JSON object, so its first byte is `{` (0x7B).
Writers encode with object keys sorted recursively by their UTF-8 bytes, no insignificant
whitespace, slashes unescaped, non-ASCII characters as UTF-8, and the minimal escapes JSON
requires. Numbers follow the serde_json 1.0.145 writer with Ryū formatting: integer tokens
within the signed or unsigned 64-bit range in decimal without leading zeros; other numbers as
IEEE-754 binary64, correctly rounded, written as the shortest round-tripping decimal with
lowercase `e`, no exponent leading zeros or positive sign, and `.0` for integral floats in fixed
notation; `-0.0` for negative zero; `1` and `1.0` are different bytes; non-finite numbers are
forbidden. **Readers verify the exact received body bytes and never re-encode them for
signing.** Every `/5` body MUST be canonical: a reader re-encodes the parsed value and refuses
the object as `malformed` if the bytes differ. Older bodies inside an upgraded account are
verified as their own version required.

### 2.2 Other encodings

- **Bytes** are standard padded base64. 0.5 readers refuse any other spelling, including
  non-zero padding bits, as `malformed`. `requestId` alone is unpadded base64url (§12.2).
- **Embedded envelopes** (a request in a grant, a link in a call, heads in evidence) are the
  standard padded base64 of the embedded envelope's canonical JSON bytes.
- **Dates**, everywhere in 0.5 including `terms.expires`, are UTC `YYYY-MM-DDTHH:mm:ssZ` or
  `YYYY-MM-DDTHH:mm:ss.sssZ` with exactly three fraction digits. The calendar date and time
  MUST exist (no February 30, no hour 24, no second 60); anything else is `malformed`, never
  "no expiry". Comparison uses the components with omitted milliseconds as zero.
- **Digests** are lowercase hex SHA-256 of exact bytes, 64 characters unless "first 32".
- **Integers** in fields defined here are integer tokens from 0 to 2^53−1 unless stated.
- **Equality** of authority entries, records, heads and receipts is equality of their body bytes.
  Two envelopes over one body are the same object; the first one received is kept.
- **Signature bytes are never identifiers.** ECDSA signatures are malleable (high-S is valid,
  §4.3), so no record, cache, replay store or index may be keyed by signature bytes or by a
  digest of an envelope that includes them; use body digests, `requestId`s and key IDs.

### 2.3 Strict parsing and closed field sets

- Any JSON object, at any depth, with a duplicate member name is `malformed`, including
  `clientData` and operation payloads.
- Every object this document defines has exactly the fields it lists. Optional fields MUST be
  omitted when absent. `null` appears only where a rule allows it. Arrays called non-empty MUST
  NOT be empty. A field of the wrong type is `malformed`.
- An unknown field, kind, form, role, slot kind, term or value inside a known protocol is
  handled by §1: `newerFormat` only after everything that authenticates and authorizes the
  object has passed.
- Unknown `clientData` members are ignored. Operation payloads, import evidence and module
  values follow their own schemas and MAY contain `null`.

### 2.4 Bounds

| Object | Bound on canonical bytes |
| --- | --- |
| Authority body (`/5`), transition body | 1,048,576 |
| Receipt, veto body | 1,024 |
| Membership request body | 16,384 |
| Link body | 8,192 |
| Call body, including embedded links | 65,536 |
| `args` of a call | 16,384 |
| Head body | 4,096 |
| Equivocation evidence | 2,097,152 |
| Operation header body (including `ciphertext`) | 16,777,216 |
| `clientData` | 8,192 |

Exceeding a bound is `malformed`. A verifier MUST NOT allocate in proportion to a claimed length
before checking it.

**Portability floor.** Every service and verifier MUST be able to verify, on first contact, an
account whose history and pending objects together have at least:
- 65,536 authority entries;
- 4,096 transitions, vetoes and receipts;
- 256 MiB of envelopes;
- 262,144 signature verifications, counting every signature of authority entries, transitions,
  vetoes, receipts, heads, `handover`, `additions` and embedded requests.

Pages hold at most 64 entries (§14). A service MAY set higher limits, MUST document its limits,
and answers `unavailable` beyond them, never partial validity. It MUST NOT impose a time limit
that refuses an account within the floor; clients MAY verify in the background. Verification
resumes from persisted state (§13.3). The rate limits of §13.1 keep an honest account far below
the floor. Hosts MUST warn the owner when an account passes half of it.

## 3. Keys

### 3.1 Key descriptor

```json
{"form":"raw","signing":"<base64>","agreement":"<base64>"}
{"form":"webauthn","signing":"<base64>","rp":"id.luff.works","credential":"<base64>",
 "origins":["android:apk-key-hash:<base64url>"],
 "authorityOrigins":["android:apk-key-hash:<base64url>","https://id.luff.works","https://keys.id.luff.works"]}
```

| Field | Rule |
| --- | --- |
| `form` | `raw` or `webauthn`. |
| `signing` | A valid uncompressed 65-byte P-256 point. |
| `agreement` | `raw` only, optional. A valid 65-byte point. Required to open a `sealed` slot or part. |
| `rp` | `webauthn` only, required. 1–253 bytes: dot-separated labels of 1–63 lowercase ASCII letters, digits and `-`, no label starting or ending with `-`. |
| `credential` | `webauthn` only, required. 1–1,023 bytes. A lookup hint; it never affects verification. |
| `origins` | `webauthn` only, optional. 1–32 distinct strings, strictly ascending by bytes. Each is a **web origin**, `https://` followed by a host in the `rp` grammar and nothing else, or a **platform origin**, 1–512 printable ASCII bytes not starting with `http:` or `https:`. |
| `authorityOrigins` | `webauthn` only, optional. 1–32 distinct origins, strictly ascending, each allowed for this descriptor by §4.3's general rule. |

The **key ID** is the first 32 lowercase hex characters of SHA-256 of `signing`.

### 3.2 What `rp` means

`rp` is the WebAuthn relying-party ID the credential belongs to. WebAuthn binds a passkey to it
forever, every assertion carries SHA-256 of it, and **every origin a browser lets use that
`rp` (the `rp` itself, every subdomain, and any related origin the `rp` publishes) can ask that
passkey for a signature over any challenge and for the PRF output for any salt.** Slot salts
are in the account's history, so any such origin can open that passkey's `prf` slots (§7.2).
Therefore:

- A host that registers a keyring passkey MUST use an `rp` whose every subdomain and related
  origin is operated as a ceremony origin of one release channel, and MUST NOT let a release of
  a different channel (for example staging) run code on any of them. A non-production release
  MUST use a different `rp` for any passkey it creates.
- Separating ceremony origins under one `rp` (for example an authority origin and a call origin)
  separates which origin can obtain **authority signatures** (via `authorityOrigins`). It does
  **not** separate **vault access**: every origin under the `rp` can read every `prf` slot of
  its passkeys. Code that must never be able to open the vault must not run on any origin under
  that `rp`; it needs its own `rp`, and therefore its own passkeys.
- Native builds are origins too. A beta or test build (TestFlight, an internal track) of an app
  is another release channel: it MUST NOT be listed in the production `rp`'s association files,
  or it MUST use another `rp`.
- **Security invariant:** whoever controls code on any origin a browser allows for an `rp` can
  read every `prf` slot of that `rp`'s passkeys. No field in an account changes this.
- The bare `rp` origin SHOULD serve only `/.well-known/` association files, because native-app
  assertions are commonly reported with that origin and it is then in `authorityOrigins`.

A verifier's own domain, origin or deployment never enters verification (§4.3).

### 3.3 One key, one principal, across time

A **principal** is one controller (by ID), one member (by ID) or one vault generation. Across
one account's whole history:

1. Within a principal, `signing` and `agreement` MUST be different points.
2. Every P-256 point used for signing or agreement, and every key ID, belongs to exactly one
   principal and one usage, for ever. In particular an entry that adds as a controller any key
   that is or ever was a member key, member agreement key or vault key of this account, and a
   grant to any key that is or ever was a controller, member or vault key, are `malformed`.
3. A principal repeats its own keys only by remaining the same principal: a retained
   controller, a controller re-added after removal (§8.3), or the unchanged current vault.
4. A link's `to.signing` (§12.1) MUST NOT be any principal's point in the history the verifier
   holds, and MUST NOT repeat within one call.

This rule is per account. The same passkey MAY control any number of accounts; that is
linkable by anyone who sees both histories, because key IDs and descriptors are public. 0.5
offers no unlinkable or pairwise account references: a person who wants two accounts not to be
linkable uses different keys for each. Hosts SHOULD refuse to add as a controller a key they
know as a member of any account.

### 3.4 Private-key work stays in the host

The core holds no platform private key. Every signature, ECDH and PRF evaluation is
two-phase: `begin_*` returns the exact input, `finish_*` verifies the result before using it.
The vault seed is an account secret: the core MAY hold it in memory for a session and MUST NOT
persist it; the host persists it only inside slots.

### 3.5 COSE_Key at registration

The credential public key MUST be a definite-length CBOR map with exactly five entries and no
duplicate keys: 1 (kty) = 2; 3 (alg) = −7; −1 (crv) = 1; −2 (x) and −3 (y), 32-byte byte
strings. Minimal integer and length encoding; nothing after the map. The key is
`0x04 ‖ x ‖ y` and MUST be a valid point. Anything else is `malformed`. Attestation MAY be
recorded and MUST NOT be required.

## 4. Signatures

### 4.1 Envelope

```json
{"body":"<base64>","signature":"<base64>",
 "assertion":{"authenticatorData":"<base64>","clientData":"<base64>"},
 "cosignatures":[{"signer":"<keyID>","signature":"<base64>","assertion":{}}],
 "additions":[{"signer":"<keyID>","signature":"<base64>","assertion":{}}],
 "handover":[{"signer":"<keyID>","signature":"<base64>","assertion":{}}]}
```

- `assertion` is present if and only if the signer's form is `webauthn`; likewise in each item.
- `cosignatures`: absent or non-empty, sorted by `signer`, distinct from each other and from
  `by`; signers are controllers of the keyring that authorizes the entry.
- `additions`: absent or non-empty, sorted by `signer`; each is a **possession proof** by a
  controller the entry adds (§8.4). It never counts toward a rule.
- `handover`: only on a genesis with `predecessor`; signers are predecessor keys (§15.1).
- A signer appears at most once in each list. Every attached signature MUST verify; one failing
  or foreign signature makes the whole object `badSignature`.
- `activate` (except for a vault change) and `vetoed` entries carry only `body` (§8.7).
- Requests, links, heads, receipts and operation headers carry exactly `body` and `signature`,
  signed `raw`. A call carries `body`, `signature` and, when signed by a WebAuthn controller,
  `assertion`. Any other field on these is `malformed`.

### 4.2 `raw`

`signature` is 64 bytes, `r ‖ s`: ES256 over the exact body bytes. `r` and `s` are in [1, n−1];
high-S values are valid, and a library enforcing low-S normalizes before verifying.

### 4.3 `webauthn`

A verifier MUST check, in order:

1. `clientData` parses under §2.3 and has `type` `"webauthn.get"`, `challenge` equal to the
   unpadded base64url of SHA-256(body), an allowed `origin` (below), and `crossOrigin` absent or
   `false`. Other members are ignored.
2. `authenticatorData` is at least 37 bytes and bytes 0–31 equal SHA-256 of the UTF-8 `rp`.
3. Flags (byte 32): UP (0x01) set; UV (0x04) set when the controller has `verification: true`
   and for every signature a rule here marks "with UV". All other flags (backup eligibility,
   backup state, attested data, extension data) and every byte after byte 36 are ignored.
4. The sign counter (bytes 33–36) is ignored for validity. A host MAY record it for display; no
   verifier refuses on it.
5. `M = authenticatorData ‖ SHA-256(clientData bytes)`. `signature` is exactly
   `0x30 ‖ len ‖ 0x02 ‖ rlen ‖ r ‖ 0x02 ‖ slen ‖ s`, nothing after; each length one byte below
   0x80, `len = rlen + slen + 4`; `r` and `s` 1–33 bytes, first byte at most 0x7F, a leading
   0x00 only before a byte of 0x80 or more; both in [1, n−1]. Verified as ES256 over
   SHA-256(M). High-S is valid; a library enforcing low-S normalizes `s` to `min(s, n−s)` after
   these checks. Stored bytes never change.

**Allowed origins (general rule).** An origin is allowed when it is a member of `origins`, or
is `https://` followed by a host with no port, path, query, fragment or user information (none
of `/ : ? # @ \`) that equals `rp` or ends with `.` ‖ `rp` with a non-empty prefix not starting
or ending with `.` and not containing `..`.

**Authority origins.** A signature on an authority entry, a transition, a veto, an `additions` item or a `handover`
item is valid only from an origin in `authorityOrigins` when that field is present, and
otherwise only from exactly `https://<rp>` or a platform origin listed in `origins`. Hosts that
follow §18 set `authorityOrigins` at registration to their authority-ceremony origin, the bare
`https://<rp>` when their native apps report it, and their native-app platform origins.

**Call origins.** A verifier of a **call** signed by a WebAuthn controller MUST also refuse it
unless the origin is one of the call-ceremony origins it has configured for that controller's
`rp` (§12.3 step 5).

**Where the verifier is does not matter.** A verifier MUST NOT compare `origin`, `rp` or
anything else with its own origin, host or deployment. A service MAY refuse a call for local
reasons; it MUST NOT refuse an authority entry, receipt or head that this document accepts,
because authority validity must agree across readers.

## 5. Accounts and references

### 5.1 The account identifier

An account's **ID** is all 64 lowercase hex characters of SHA-256 of its first authority body.
Its text form is `colophon:` followed by the ID.

An account upgraded in place from 0.4 (§16.1) keeps its first entry, so its 0.5 ID is the full
digest whose first 32 characters are its 0.4 library ID. A 32-character ID is a **legacy
library ID**: it appears only inside 0.4 entries and `/3` operation headers of an upgraded
account, and anywhere a 0.5 format names an account it is `malformed`. A legacy ID found outside
an account is resolved only by obtaining the history and checking the prefix.

### 5.2 References and hints

```json
{"account":"<64 hex>","hints":["https://home.example/v1/accounts/<64 hex>"]}
```

- `hints` is optional: 1–8 `https://` URLs of at most 512 bytes. Never signed, never digested.
- A hint is untrusted; what it returns is checked under §8, or dropped.
- A reader fetching a hint sends no cookie, credential, call or account secret; bounds size,
  time and redirects (at most 5); and on a server refuses loopback, private, link-local,
  unique-local and cloud-metadata destinations after every resolution and redirect, checking the
  address actually connected. A client that lets a user allow a local destination asks and says
  the hint's owner learns of the lookup.

## 6. Controllers and the keyring

### 6.1 Controller

```json
{"key":{…},"label":"Passkey","roles":["approve","control"],"verification":true,"holder":"mike"}
```

| Field | Rule |
| --- | --- |
| `key` | A key descriptor (§3.1). |
| `label` | 1–200 bytes. Display only; hosts show the key ID and first-seen seq beside it. |
| `roles` | Non-empty, sorted, duplicate-free subset of `approve`, `control`, `recover`, `sign`. `sign` appears only alone. |
| `verification` | `webauthn` only. Present only as `true`: every signature needs UV. |
| `holder` | Optional, 1–64 bytes: a label for the person or custody unit holding the key. Required on every controller when `countBy` is `holders`. |
| `audiences` | Present if and only if roles are `["sign"]`. 1–32 distinct sorted audiences (§10.1 grammar). |

The controller ID is its key ID. A controller is always a key, never another account.

| Role | Can |
| --- | --- |
| `approve` | Make the member entries of §8.4 under the single rule (admit, renew and revoke members other than homes; end sessions; introduce epochs). **The control threshold does not protect these;** `memberRule` `control` makes them need it. |
| `control` | Propose and veto transitions (§8.7); make immediate additive entries; suspend. |
| `recover` | Propose recovery transitions; consent to recovery-set changes; veto; suspend; read the history (§13.4). |
| `sign` | Sign calls at its `audiences` only. Nothing else. |

**Counting units.** Under `countBy: keys` a unit is a key ID. Under `holders` it is a `holder`
value, and each holder counts once however many of its keys sign (at least one valid signature by
a current key of that holder is needed). Every count in this document uses units: thresholds,
signers, vetoers, escalation and the two-unit minimum of the full set. A `holder` is a label the
controllers attest, not proof of separate people. Setting or changing one is a pending
transition that the labelled key signs.

### 6.2 Keyring

```json
{"controllers":[…],"threshold":1,"recoverThreshold":1,"addThreshold":1,"countBy":"keys",
 "policy":{…},"vault":{"signing":"…","agreement":"…"},"slots":[…]}
```

| Field | Rule |
| --- | --- |
| `controllers` | 1–64, sorted by ID, no duplicates; at least one holds `control`. A `keyring` entry MUST NOT leave more than 56; only `activate` may use the rest. |
| `countBy` | `keys` or `holders` (§6.1). |
| `threshold` | 1 to the number of `control` units. |
| `recoverThreshold` | 0 if no controller holds `recover`; otherwise 1 to the number of `recover` units. |
| `addThreshold` | 1 to `threshold`: units needed for an immediate addition. |
| `policy` | §6.3. |
| `vault` | The vault's public identity (§7.1). |
| `slots` | 1–256. A `keyring` entry MUST NOT leave more than 224; only `activate` may use the rest. |

### 6.3 Policy

`policy` has exactly these fields (`primaryHome` optional). They bind every verifier of the
account; a verifier MAY be stricter for calls only.

| Field | Meaning | Range |
| --- | --- | --- |
| `callWindow` | Seconds a call's `created` may differ from the verifier's clock (§12.3) | 30–3,600 |
| `headMaxAge` | Seconds a head stays fresh (§13.3) | 30–86,400 |
| `headQuorum` | Distinct homes whose fresh heads or receipts are needed (§12.3, §8.7) | 1–8 |
| `history` | Who a home serves the history to: `members` or `public` (§13.4) | — |
| `linkMaxAge` | Most seconds from a link's `notBefore` to its `expires` | 60–2,592,000 |
| `memberRule` | `single` or `control` (§8.4) | — |
| `primaryHome` | Member ID of the primary home. Absent: the earliest-appointed current home. | a current home |
| `recoveryDelay` | Seconds a pending transition waits for a veto (§8.7) | 0–2,592,000, and at least 3,600 while the account has a home |

An entry that leaves the account with one or more homes and `recoveryDelay` below 3,600, or with
fewer current homes than `headQuorum` while it has any home, or names as `primaryHome` a member
that is not a current home, is `malformed`. Which policy changes are immediate and which are
pending is in §8.4.

### 6.4 Warnings

Hosts MUST warn, in words, before writing anything after which:

- losing any one key (or holder) leaves no control quorum, no recovery quorum the person chose, or
  no openable slot;
- fewer recovery controllers exist than the person chose, or none has a slot;
- **the account has a `recover` controller and no home: "Without a home nothing waits and nothing
  can be vetoed: anyone with one of your keys can take the account at once."**;
- the account has one home: "If your only home is down, nothing that has to wait can take
  effect. If it turns against you while someone has one of your keys, you can lose the account.";
- every control key is on one device (for example a phone's device key and its synced passkey):
  "A thief with this phone holds every control key. Keep one on another device.";
- only one `recover` controller exists, or all recovery keys are kept together: "Someone who
  takes them can take your account. Keep two, apart.";
- a company has two holders and `threshold` 2 ("neither of you can be removed without the
  other") or `threshold` 1 ("either can act alone").

## 7. Vault and slots

### 7.1 Vault

The vault seed is 32 random bytes from the host. Its identity is
`s' = HKDF-SHA256(IKM = seed, salt = "colophon/vault/4", info = "identity", 32 bytes)`, then the
software-identity procedure of §7.5 on `s'`. The `/4` in these and the slot labels is a
domain-separation label, unchanged in 0.5.

**Each newly introduced epoch MUST be sealed to exactly the current vault and the active,
unexpired members with any access to its namespace (§10.2), at the introducing entry.**
Historical seals stay valid. Later `shares` add only recipients this document authorizes.

After opening any slot the core MUST check the plaintext is 32 bytes, derive the identity and
compare both public keys with the keyring's `vault`; a mismatch is `refused:vaultLocked` and
leaves the session's seed unchanged.

### 7.2 Slots

Every slot has exactly `kind`, `controllers` (IDs of current controllers, none of them `sign`), `label` (1–200 bytes) and its kind's fields:

```json
{"kind":"sealed","controllers":["<id>"],"label":"iPhone","sealed":{"enc":"<base64>","ciphertext":"<base64>"}}
{"kind":"prf","controllers":["<id>"],"label":"Passkey","salt":"<base64>","box":"<base64>"}
{"kind":"combined","controllers":["<id0>","<id1>"],"label":"Kit and passkey",
 "parts":[{"kind":"sealed","sealed":{"enc":"…","ciphertext":"…"}},{"kind":"prf","salt":"…"}],"box":"<base64>"}
```

```text
I  = "colophon/vault-slot/4\n" ‖ vaultID ‖ "\n" ‖ kind ‖ "\n" ‖ join(controllers, ",")
Ii = "colophon/vault-part/4\n" ‖ vaultID ‖ "\n" ‖ decimal(i) ‖ "\n" ‖ part.kind ‖ "\n" ‖ controllers[i]
```

`vaultID` is the key ID of the vault's signing key. Parts are zero-indexed; part secrets are 32
bytes, concatenated `S0 ‖ … ‖ S(n−1)`.

| Kind | Shape | Opening |
| --- | --- | --- |
| `sealed` | One `raw` controller with `agreement`. `sealed` is `{enc (65-byte point), ciphertext (48 bytes)}`. | HPKE (§11.1 suite) to that agreement key, `info` and AAD `I`. Plaintext is the seed. |
| `prf` | One `webauthn` controller. `salt` 32 bytes, `box` 60 bytes. | PRF output `P`. Key = HKDF-SHA256(IKM `P`, salt `salt`, info `I`, 32 bytes). `box` = nonce(12) ‖ AES-256-GCM(seed, AAD `I`) ‖ tag. |
| `combined` | ≥ 2 distinct controllers; `parts` same length and order; `box` 60 bytes. A part is `{"kind":"sealed","sealed":…}` for a `raw` controller with `agreement`, or `{"kind":"prf","salt":…}` for a `webauthn` one. | Sealed part: HPKE with `Ii`. PRF part: HKDF(IKM `P`, salt, info `Ii`). Key = HKDF-SHA256(IKM `S0 ‖ … ‖ Sn−1`, salt empty, info `I`, 32 bytes); `box` as for `prf`. |

Each sealed part encrypts a fresh independent random 32-byte secret, never the seed, never
reused. A wrong secret is `refused:vaultLocked`. Structural violations are `malformed` at replay.

**A `prf` slot is readable by every origin that can exercise its credential** (§3.2). A person
who wants no single web origin to be able to open the vault uses a `combined` slot that also
needs a device key or a kit, and no standalone `prf` slot; hosts SHOULD offer this as a setting.

**PRF bytes.** `salt` is the exact WebAuthn PRF input (`prf.eval.first`); `P` is the 32-byte
`results.first`. A CTAP `hmac-secret` host applies SHA-256(`"WebAuthn PRF"` ‖ 0x00 ‖ salt) and
selects the UV-associated secret. Missing PRF fails explicitly; there is no fallback.

**Building a PRF route.** The PRF output for a new slot or part MUST come from an assertion
restricted to that slot's credential, evaluating its salt over a fresh random 32-byte core
challenge (never a body digest), never from registration. The core verifies that assertion
against the new controller's key, builds the slot, opens it again with the same output and
checks the vault before it is published. The host is trusted to pass PRF bytes unchanged.

### 7.3 Pairing

Pairing joins two devices that a person can see: a **joining** side J holding a key point `E`
(an ephemeral transfer key, §7.4, or a new member's signing key, §9.1) and an **existing** side
H. All inputs are raw bytes: `accountID` is its 64 ASCII hex characters, `E` the 65-byte
uncompressed point, `nA` and `nB` 32 bytes each.

1. J chooses `nB` at random and sends `C = SHA-256("colophon/pair/5" ‖ accountID ‖ E ‖ nB)`.
2. Only after receiving `C`, H chooses `nA` at random and sends it.
3. J sends `E` and `nB`. H checks `C`; a mismatch aborts.
4. Both display the code: the first four bytes of
   `SHA-256("colophon/pair-code/5" ‖ accountID ‖ E ‖ nA ‖ nB)`, big-endian, modulo 1,000,000,
   as six digits. The person confirms they match.

Each commitment permits exactly one reveal. A mismatch, abort or timeout ends the session; a
retry starts again with new nonces, and H MUST allow no more than 5 failed sessions per hour. A
relay that substitutes `E` must commit before it sees `nA`, so it matches the code with
probability one in a million per attempt. **QR alternative:** H scans from J's screen a QR code
carrying `accountID`, `E` and `nB`, checks `E` directly, and still sends `nA` to J, so that
§7.4's label has both nonces; no code is compared.

### 7.4 Moving the seed to a new device

To add a controller whose ceremony happens on a device without the seed (§17.3): the new device
generates an ephemeral P-256 agreement key `E`; the devices pair (§7.3); the seed holder seals
the seed with HPKE (§11.1 suite) to `E` with `info` and AAD
`"colophon/vault-transfer/5\n" ‖ accountID ‖ "\n" ‖ keyID(E) ‖ "\n" ‖ hex(nA) ‖ hex(nB)`; the
new device opens it, checks the vault, builds its slot, and erases the seed and `E` when the
session ends. Offered only to a device about to become a controller with a slot.

### 7.5 Software identities and kits

A software identity is expanded from a 32-byte seed with HKDF-SHA256, salt
`colophon/entropy/3`, info the eight-byte big-endian counter from zero, 32 bytes: the first
valid scalar signs, the next valid scalar agrees; invalid scalars consume a counter. A recovery
kit is a software identity from 32 secret bytes the host prints or stores; it is a `raw`
controller with `agreement`, usually `recover` only.

## 8. Authority history

### 8.1 Body

Every authority body has `protocol`, `seq` (contiguous from 1), `previous` (SHA-256 hex of the
exact preceding body, `null` only at seq 1), `issued`, `by` (the primary signer's ID), `kind`
and the kind's fields. New accounts use `colophon/authority/5` from seq 1. An upgraded account
has `colophon/authority/4` entries up to and including its `upgrade` entry and `/5` after it
(§16.1). Any other mixture is `malformed`.

`issued` MUST NOT be earlier than the preceding entry's `issued` (`malformed`). An entry whose
`issued` is more than 60 seconds after the verifier's clock is *held* until it is not.

### 8.2 Kinds

| Kind | Fields | Effect |
| --- | --- | --- |
| `genesis` | `label` (1–200 bytes), `namespaces`, `keyring`, optional `predecessor` | Creates the account. The vault MUST be fresh. |
| `rekey` | `epochs` (non-empty, at most one per namespace) | Introduces epochs. **If the account declares namespaces, seq 2 MUST be a `rekey` introducing epoch 1 for exactly the declared namespaces.** |
| `grant` | `request`, `terms`, `shares` | Admits a new member (§9.2). |
| `renew` | `member`, `expires`, `shares` | Extends a member's expiry (§9.4). |
| `revoke` | `member`, `kept`, `heads`, `epochs` | Ends a member (§9.5). |
| `endSessions` | `member` | Ends every link under a member (§9.6). |
| `keyring` | `keyring` | An immediate additive keyring change (§8.4). |
| `suspend` | `key`, `transition` | Suspends a key while a transition removing it is pending (§8.7). |
| `activate` | `transition`, `receipts`, and for a vault change `shares` and `epochs` | Applies a due transition (§8.7). |
| `vetoed` | `transition`, `veto`, `receipts` | Records a vetoed transition (§8.7). |

`namespaces` is 0–64 distinct sorted names of lowercase ASCII letters, digits, `.` and `_`, at
most 128 bytes. A `/5` account is at layout 2 from genesis (§11.8). Raising the layout and
writing `migration` are transitions (§8.4).

### 8.3 Keyring changes and the vault

Immediate `keyring` entries only add or tighten (§8.4); transitions do the rest (§8.7). When the
vault is unchanged, every existing slot stays (multiset by canonical JSON without `label`), and
labels and order may change.

**Rotation is required** when a controller that any slot or part in this account's history has
named is removed, loses a role, or has its `agreement` changed, and when a slot is deleted or its
cryptographic fields change. The transition doing that MUST also change the vault, in the same
`change` (§8.7). A never-slotted controller is removed or demoted without rotation. A removed
controller may be re-added as the same principal (§3.3); slots naming it must be new.

**A vault change** names the fresh new vault and its slots. At activation:
- it MUST contain a slot for every controller that had one at the anchor and remains a controller
  after the change;
- slots added after the anchor, and slots of controllers it removes, are dropped, and hosts
  rebuild them by immediate entries after activation;
- the `activate` carries `shares` (every epoch existing at activation, sealed to the new vault)
  and `epochs` (a new epoch in every namespace), built by a signer of the transition who holds the
  new seed.

Hosts MUST build every new slot to open the new vault; verifiers can't check that.

### 8.4 Who may sign what

Signers are evaluated against the state immediately before the entry; for a transition, before
its `activate` (§8.7). `sign` controllers never count.

**Immediate entries.** The last column answers: can one key use this to disarm, outlast or lock
out the others?

| Kind | Rule | One key's worst use, and its bound |
| --- | --- | --- |
| `genesis` | Control rule over its keyring; possession; predecessor rule (§15.1) | — |
| `grant`, `renew`, `revoke` (not homes, not `import`) | Single rule; control rule when `memberRule` is `control` | Admit or revoke members: bounded by the rate limit (§13.1) and suspension; members a removed key admitted are listed for one-action revocation (§17.5) |
| `rekey`, `endSessions` | Single rule (one `control` signer also suffices for `rekey`; the member rule for `endSessions`); control rule when `memberRule` is `control` | Churn epochs or sessions: rate limit; one epoch per namespace per entry |
| `keyring` | `addThreshold` units holding `control`, with UV, plus possession. It may only: add controllers whose roles are `["approve"]` or `["sign"]` (with slots for them in the same entry); add slots for existing non-`sign` controllers; change labels; and tighten the **signing controller's own** authentication or policy (§6.3 lowering only). | Plant approve keys: rate limit and the 56/224 headroom; they never count or veto |
| `suspend` | One signer of the pending removal it cites (§8.7) | Suspend one owner key: costs a veto, after which escalation stops repeats |
| `activate`, `vetoed` | §8.7 | — |
| `upgrade` (`/4`) | 0.4 control rule (§16.1) | — |

**Pending transitions.** Everything else, including unknown change members and anything in
doubt. Each needs the control rule unless stated:

| Change | Also |
| --- | --- |
| Remove or demote a controller; add `control` or `recover` | The recovery rule may also propose these, removing only controllers without `recover`, and adding only `approve` when `recoverThreshold` < `threshold` |
| `threshold`, `addThreshold`, `recoverThreshold`, `countBy` | Count the larger of old and new `threshold` |
| Another controller's descriptor, `verification`, `origins`, `authorityOrigins` or `holder`, in either direction | The labelled key signs a holder change |
| Delete or change a slot; change the vault | — |
| Appoint, renew or revoke a home; a grant with `import`; `primaryHome`, `headQuorum`, `recoveryDelay` | — |
| Raise `headMaxAge`, `callWindow`, `linkMaxAge`; `memberRule` to `single`; `history` to `public` | — |
| `layout`; `migration` (only with a `predecessor`); `successor`; `resolve` (control rule of the keyring before the fork) | — |

**Recovery-set consent.** When the state before activation has `recoverThreshold ≥ 1`, a
transition also needs `recoverThreshold` `recover` units if any component:
- removes, demotes or adds `recover`;
- changes a `recover` controller's fields other than `label`, or its slot;
- changes the vault while a `recover` controller has a slot;
- changes `recoverThreshold`, `recoveryDelay`, `countBy`, `headQuorum`, `primaryHome` or homes;
- raises `threshold`;
- is `layout`, `migration`, `successor` or `resolve`.

**Rules.**
- **Control rule:** `control` units at least the larger of the old and new `threshold`; other
  signers may hold `control` or `recover`; UV on every WebAuthn signature.
- **Recovery rule:** every signer holds `recover`; at least `recoverThreshold` units; UV.
- **Single rule:** exactly one signer holding `approve`.
- **Member rule:** `endSessions` signed `raw` by the member it names.
- **Possession:** every controller added, and every controller whose `holder` is set, signs the
  body in `additions`, from an authority origin (a `sign` controller's from any origin its
  descriptor allows), with UV if it has `verification`. Exempt: `upgrade`, and keys carried over
  by a verified succession (§15.1).

### 8.5 Verification order

For seq > 1 the verifier MUST, in this order:

1. Bounded generic parse (duplicates refused). Header: `protocol` (as §8.1 allows here), `seq`,
   `previous`, `issued` (format and monotonic); failure is `malformed`. `by` names a controller of
   the prior keyring (or, for `endSessions`, a current member; for `activate` and `vetoed`, the
   `by` of the embedded transition or veto), else `badSignature`. An `issued`
   more than 60 s ahead of the verifier's clock: *held*.
2. Verify every attached signature (§4) against the prior keyring, member table or added
   controllers. Any failure: `badSignature`.
3. Decide the rule (§8.4; unknown kinds use the control rule). Not met: `badSignature`. For
   `activate` and `vetoed`, check the embedded transition, veto and receipts under §8.7; an
   `activate` whose transition isn't yet due is *held*.
4. Only now look for unknown content anywhere in the body. Found: `newerFormat`.
5. Apply the typed schema, bounds and the rules of §6, §8.2, §8.3, §9, §13, §15 and §16. A
   violation: `malformed`.

Genesis follows the same order with its own keyring. No verifier may be stricter or more
lenient than this section for authority entries.

### 8.6 Conflicting entries

Entries are equal when their bodies are equal. Two **conflicting** entries are valid entries with
the same `seq` and `previous` and different bodies. A verifier classifies a conflict between X and
Y:

1. **Activation order.** If X is `activate` or `vetoed` and Y is not, X stands only if Y's
   `issued` is later than X's transition's due time; otherwise Y stands and X belongs after the
   current head (§8.7). Between an `activate` and a `vetoed` of one transition, `vetoed` stands if
   its veto is valid (§8.7). Between entries for different transitions, the earlier due time
   stands, then the lower transition-body digest. Every such case decides only order: both
   entries are authorized, and the other is re-appended.
2. **Equivocation.** Otherwise, if X is covered by heads of `headQuorum` current homes or by the
   verifier's high-water mark, and no current home's head covers Y, Y is equivocation evidence
   against its signers. The evidence object is §13.3's, with `entries` in place of `heads`.
3. **Fork.** Otherwise (including any conflict in an account without homes), the verifier answers
   `refused:fork` for everything that depends on either branch until a `resolve` transition
   activates on one branch. A transition anchored on a losing branch is void.

The high-water mark moves to another branch only by rule 1 or an activated `resolve`. Records
citing a seq at or after an unresolved fork are held.

### 8.7 Pending transitions

```json
{"protocol":"colophon/transition/5","account":"<64 hex>","anchor":{"seq":41,"digest":"<64 hex>"},
 "issued":"…","by":"<keyID>","signers":["<keyID>","…"],
 "change":{"keyring":{"remove":["<id>"]},"vault":{"vault":{…},"slots":[…]}}}
```

**Object.**
- `signers` is the sorted list of every signing key ID. An envelope whose signatures don't match
  `signers` exactly is `malformed`.
- Signatures are authority signatures for §4.3: authority origins, and UV for WebAuthn.
- `anchor` names an entry the proposer verified, binding the transition to its branch. `issued` is
  not earlier than the anchor's.
- `change` has one or more components: `keyring` (`add`, `remove`, `update` with whole replacement
  controllers, `threshold`, `recoverThreshold`, `addThreshold`, `countBy`), `policy` (fields to
  set; `primaryHome: null` unsets it), `vault` (`{vault, slots}`), `homes` (`appoint:
  [{request, terms}]`, `revoke`), `grant` (`{request, terms}` with `import`), `layout`,
  `migration` (§15.4), `successor` (`{account}`), `resolve` (`{discarded: {seq, digest}}`).
- Its rule, recovery-set consent and affected roles are the union of its components'. It
  activates atomically or not at all.

**Delta semantics at activation.**
- `remove` of an absent ID, or `add` of a key already present with the same roles, does nothing.
- `add` of a present key with different roles, or `update` of an absent ID, voids the
  transition.
- Thresholds are absolute values.
- A transition that changes nothing, or whose result breaks §6, is void.

**Evaluation point.** A transition is valid at an `activate` entry only if, against the state
immediately before that entry:
- its signers meet the rule, consent and escalation;
- each signer is still a current controller holding the role it signed with;
- its receipts come from homes current in that state;
- its anchor is on that branch.

The delay is the larger of `recoveryDelay` at the anchor and in that state. "No home" means that
state has no home.

**Receipts and due time.**
- Each current home receipts a transition (§13.5) when it meets the same conditions against the
  home's latest state, its `issued` is within 300 s of the home's clock, and the home holds
  fewer than 32 pending transitions for the account and fewer than 2 by the same proposer.
- The transition is **due** at the `headQuorum`-th smallest `received` among valid receipts by
  distinct current homes, plus the delay. An entry that relies on a due time carries exactly those
  receipts.
- With no home, it is due when issued.

**Veto.**
- `{"protocol":"colophon/veto/5","account","transition":"<body digest>","issued","by","signers":[…]}`,
  signed by at least as many units as the transition. Every signer is a current `control` or
  `recover` controller that didn't sign it; a key the transition would remove may sign.
- Signatures are authority signatures (authority origin, UV).
- A veto is **valid** when receipted by `headQuorum` distinct current homes with `received` before
  the due time.
- A home that holds a valid veto MUST append `vetoed`.

**Activation.**
- A due, unvetoed transition is applied by an `activate` entry whose body is determined:
  - `by` is the transition's `by`;
  - `issued` is the later of the due time and the preceding entry's `issued`;
  - `receipts` are the receipts defining the due time, sorted by home ID.
- A `vetoed` entry is likewise determined:
  - `by` is the veto's `by`;
  - `issued` is the later of the latest counted veto receipt and the preceding entry's `issued`;
  - the veto and its counted receipts, sorted by home ID.
- These entries carry no signature of their own: their envelope is `{"body"}`, authenticated by
  the transition, veto and receipts embedded in it. So every home produces the same bytes.
- A vault change's `activate` also carries `shares` and `epochs`, and is signed by its `by`, who
  must hold the new seed. Two such entries for one transition at one seq are ordered by lower body
  digest; their effects are identical.
- Any current home may append `activate` or `vetoed`, after its current head (§8.6 rule 1), and
  MUST do so before storing other entries once the transition is due or the veto valid.
- An `activate` stored more than 7 days after the due time, by the home's clock, is void.

**Finality.**
- An activation is **final** at a verifier once heads of every current home cover it. Before that
  it is provisional.
- A provisional activation's removals and restrictions apply at once (fail-safe). Its additions
  don't count for calls (§12.3) until final.
- If a verifier later holds a valid `vetoed` for a transition whose `activate` it accepted, the
  `vetoed` branch stands (§8.6 rule 1) and the `activate` becomes evidence against the homes that
  covered it.
- Effects a service took only on provisional authority are the service's risk; services MUST
  NOT take irreversible effects on provisional additions.

**Escalation.**
- v(u) is the number of `vetoed` entries naming transitions signed by unit u since the last
  `activate` of a transition u signed that itself met the escalation rule then.
- A transition with signer units S needs |S| ≥ 1 + max v(u) over S. This is checked at receipt
  and again before activation, using every preceding `vetoed`.
- A unit removed and re-added keeps its count.
- It terminates: each veto raises v for every signer, and |S| can't exceed 64.
- The side with more units completes; equal sides **stall**. In a stall, both keep their
  immediate powers (subject to suspension and rate limits), and the stall ends only when one side
  obtains another unit.

**Full set.** A transition is due when issued and can't be vetoed when it has at least two signer
units and either:
- (a) it meets the recovery rule and every current `recover` controller signed it; or
- (b) it meets the control rule, every current `control` controller signed it, and, if it needs
  consent, every current `recover` controller too.

"Current" includes every key the transition removes. Whoever holds every recovery key is treated
as the owner.

**Suspension.**
- While a transition that removes or demotes key K is pending (receipted, not vetoed, not void),
  one of its signers may append `suspend` naming K and the transition's digest.
- From then until the transition activates, is vetoed or becomes void, K signs no call
  (`refused:revoked`) and no immediate entry. K may still veto.
- A signer may have one suspension outstanding.

**Calls during transitions.** A key a pending transition would add is not a controller until a
final activation. A key it would remove works until activation, unless suspended.

**No home.** There is no delay and no veto; conflicts are forks. **An account without a home has
no theft safety.**

The outcomes of theft and loss scenarios under these rules are worked through in
[colophon-0.5-changes.md](colophon-0.5-changes.md) §H.

## 9. Members

### 9.1 Membership request

```json
{"protocol":"colophon/request/5","account":"<64 hex>",
 "member":{"signing":"<base64>","agreement":"<base64>"},
 "label":"Codex on optiplex","kind":"agent","terms":{…},"created":"2026-11-11T09:00:00Z",
 "custody":"software","operator":"Example hosting",
 "service":{"endpoints":["https://home.example/v1/accounts/<64 hex>"]}}
```

| Field | Rule |
| --- | --- |
| `member` | Two distinct valid points. The member ID is the key ID of `signing`. |
| `label` | 1–200 bytes. |
| `kind` | `device`, `app`, `agent` or `server`. Signed attribution: an `agent` member's records are shown as written by AI. |
| `terms` | Terms asked for (§10). MUST NOT contain `import`. |
| `custody` | Optional: `hardware`, `platform`, `software` or `custodial`. Display. |
| `operator` | Optional, 1–200 bytes: who runs the key. Required when `custody` is `custodial`. |
| `service` | Present iff `terms.serves` is present: 1–8 distinct sorted `https://` endpoints of at most 512 bytes. Discovery data only. |

Signed `raw` by `member.signing`, stored at `requests/<memberID>.json`, immutable. Before
approval, the requesting device and the approving device MUST pair under §7.3 with `E` =
`member.signing` (or the approver scans the requester's QR code); approval of a request whose
key did not pair is a host failure the person cannot see, so hosts MUST NOT offer it.

### 9.2 Grant

`request` is the embedded request envelope, verified under its own key and naming this account.
`terms` are granted and MUST be **covered by** the requested terms: each granted `records` entry
matches a requested entry for the same namespace with equal or higher access and, if requested
`kinds` are present, granted `kinds` that are a subset; each granted `services` entry matches a
requested one for the same audience whose purposes are `["*"]` or a superset; `serves` is a
subset; `import` is added only by approvers (§9.3); `expires`, `writes`, `depth` and `conditions`
are set by approvers. Further:

- The member ID and both member points are new to this account (§3.3).
- Every granted namespace is declared; `shares` seals every historical epoch of every granted
  namespace to the member's agreement key, and is empty when `records` is absent.
- `serves` is never granted to an `agent`.

### 9.3 Import

`terms.import` (present only as `true`) lets the member publish `colophon.importBatch` (0.3
§7.2) in its namespaces; every 0.3 rule naming the root's import role names this term. An import
grant MUST give `write` in every `records` entry, have `expires` later than `issued`, use the
control rule, and be for a `device` or `app`. Readers compare a parent operation's signed
`created` with `expires` and never use first-seen time. To stop imports, revoke the member.

### 9.4 Renew

`renew` sets `member`'s expiry to `expires`, which MUST be later than both the entry's `issued`
and the member's current expiry; to shorten access, revoke. The member MUST be current.
`shares` seals every epoch in its `records` scope it lacks, including epochs introduced while it
was expired. Nothing else changes.

### 9.5 Revoke

`revoke` ends `member`. `epochs` introduces a new epoch in every namespace the member could read
(empty if none). A record by the member is **kept** exactly when:

- its header-body digest is in `kept` (sorted, distinct; any header digest, `/3` or `/5`, live
  or not); or
- it is reached by the **walk**: start at each digest in `heads` (sorted by namespace then
  digest; at most 16 per namespace, each a header of this member in that namespace) and follow
  `previous` from header to header, through any header whose body digest matches, whether or not
  that header is itself admitted.

A kept record still passes every other admission check, and a kept record citing the revocation
seq or later is refused `revoked`. A reader that cannot complete a walk because an intermediate
header is missing holds the records it would decide as *held* (`unavailable`), never as not
kept. The approver's host computes `kept` and `heads` from every record it holds, including
every fork head (up to 16) so no branch is lost. A kept record whose payload doesn't
authenticate is refused `invalidPayload`, not preserved (§11.8).

### 9.6 Ending sessions

Each member has a session number, 0 when admitted; `endSessions` adds 1. Links made under an
earlier number stop passing §12.3. Nothing already done or read is taken back.

### 9.7 What a member is never

A member is never a controller, and no later entry can make its key one (§3.3). Its key signs no
authority entry except its own `endSessions`.

## 10. Terms

### 10.1 Fields

```json
{"records":[{"namespace":"notes","access":"propose","kinds":["addNote"]}],
 "services":[{"audience":"https://projects.luff.works/scopes/7","purposes":["task.read","task.propose"]}],
 "expires":"2026-11-18T09:00:00Z","writes":500,"depth":1,
 "conditions":[{"lte":["args.amount",5000]}],"serves":["home"],"import":true}
```

| Field | Rule |
| --- | --- |
| `records` | 1–64 entries, distinct namespaces. `access` `read`, `propose` or `write`; `write` ⊃ `propose` ⊃ `read`. Optional `kinds`: 1–64 distinct kinds (1–128 bytes of `A–Z a–z 0–9 . _ -`). |
| `services` | 1–64 entries, distinct audiences. `audience`: an `https://` URL (host by the `rp` grammar, optional path, no port, query, fragment or user information) or a `urn:` URI, 1–512 printable ASCII bytes. `purposes`: `["*"]` or 1–64 distinct names of 1–128 bytes of `A–Z a–z 0–9 . _ : / -`. |
| `expires` | Inclusive last moment, a §2.2 date. Absent: no expiry. |
| `writes` | Most admitted records, counted as 0.3 §5 counts `writeBudget`. |
| `depth` | 0–4 links may follow. Absent 0. |
| `conditions` | 1–32 predicates, all must hold (§10.4). |
| `serves` | `["home"]`. |
| `import` | `true`. |

Terms contain at least one of `records`, `services`, `serves`. Link terms contain `services` and
optionally `depth` and `conditions`, nothing else.

**Audiences and deployments.** An audience is a signed string, not a proof of where a server
runs. Each deployment of a service MUST have its own canonical audience, fixed in trusted
deployment configuration, and MUST refuse every other audience. Two releases (production and
staging) are then two audiences, and a grant that names one does not reach the other.

### 10.2 Access to records and sealing

A member with any `records` entry for a namespace receives its epochs. Proposing into a
namespace one cannot read is not part of 0.5.

### 10.3 Narrowing

Link terms B narrow parent terms A (member terms or the previous link's) when every `services`
entry of B has one in A for the same audience whose purposes are `["*"]` or contain all of B's
(B's `["*"]` needs A's `["*"]`); B's `depth` is less than A's; and every predicate of A's
`conditions` equals, by canonical JSON, some predicate of B's.

### 10.4 Conditions

A predicate is `{"eq":[path,value]}`, `{"in":[path,[values]]}` (1–64 values),
`{"prefix":[path,string]}`, `{"lte":[path,number]}`, `{"gte":[path,number]}`,
`{"all":[…]}`, `{"any":[…]}` or `{"not":predicate}`.

- It reads a call's `args`, or a record's decrypted `payload`. A path is 1–8 dotted object member
  names of 1–64 bytes; a leading `args.` segment is ignored; no array indexing; a missing path
  makes the five leaf predicates false.
- `eq`, `in` compare canonical bytes; `prefix` needs two strings; `lte`, `gte` need two numbers:
  integers exactly, binary64 by IEEE-754, integer against binary64 exactly without converting the
  integer.
- Empty `all` is true, empty `any` false; `not` inverts, including a missing-path false.
- At most 32 predicates (logical ones count), nested at most 4 deep (outermost depth 1), 4,096
  bytes for the whole array; beyond is `malformed`.

The component that makes a final decision MUST see the plaintext and evaluate every predicate.

## 11. Records

### 11.1 Namespace encryption

Each namespace has consecutive epochs from 1, each a fresh 256-bit AES key. An epoch is
`{"namespace","epoch","seals":{recipientID: sealedKey}}`; a sealed key `{"enc","ciphertext"}` is
RFC 9180 base mode with KEM 0x0010, KDF 0x0001, AEAD 0x0002, one message at sequence zero; `info`
and AAD `colophon/epoch/3\n<libraryID>\n<namespace>\n<epoch>\n<recipientID>`, with `<libraryID>`
the first 32 characters of the account ID (unchanged from 0.3). Decapsulation takes raw ECDH from
the host. Hosts supply a fresh random 32-byte seed per action, expanded by §7.5.

### 11.2 Operation header

At `ops/<author>/<namespace>/<clock, 12 digits>-<id>.json`:

```json
{"protocol":"colophon/operation/5","account":"<64 hex>","namespace":"notes","author":"<memberID>",
 "epoch":1,"id":"<32 hex>","clock":7,"authority":12,"created":"2026-11-11T12:00:00Z",
 "level":"write","previous":"<64 hex or null>","nonce":"<base64>","ciphertext":"<base64>"}
```

- Signed `raw` by the author's member key; `author` and `namespace` match the path.
- `level` is `write` or `propose`.
- `previous` is the digest of this author's preceding header body in this namespace (its
  **author chain**), or `null` for its first. A member key MUST have exactly one writing process.
  A writer MUST persist its chain head before publishing, rebuild it from the store after any
  restore, and, if it finds more than one maximal head in a namespace, MUST stop writing there;
  the account then revokes the member (keeping every head, §9.5) and grants a new key.
- Optional `live` stamp `{"account","slot","generation","operationID"}` (§11.8); a live-stamped
  header has `level` `write` and `previous` `null`.
- AAD: canonical JSON of `{account, author, authority, clock, created, epoch, id, level,
  namespace, previous, protocol}`. `nonce` 12 bytes; `ciphertext` includes the 16-byte tag.

### 11.3 Plaintext and operation ID

Plaintext `{"id","kind","v","clock","authority","created","payload"}`. ID: first 32 hex of
SHA-256 of canonical `{"purpose":"colophon/operation-id/3","namespace","author","epoch","nonce",
"operation"}`, `nonce` as twelve integer octets, `operation` the plaintext with `id:""`.
Plaintext ID, clock, authority and date MUST match the header; the ID MUST verify after opening.

### 11.4 Fold order and clocks

Fold order is `(clock, author, id)`, never `created`. Clocks are positive integers at most
2^53−1; a writer increments past the highest admitted clock in the namespace; an otherwise
admissible header more than 1,024 above the highest earlier admitted clock is refused `clockJump`.

### 11.5 Admission

After the header's signature, account binding, format and path:

1. Author is a member with a `records` entry for the namespace covering `level`, at the verified
   authority (latest verified for a future claim): else refused `notGranted`.
2. `created` later than the member's latest verified expiry: refused `expired`.
3. Author revoked and record not kept (§9.5): refused `revoked` if it cites the revocation or
   later, else held `revokedBackdated`; walk incomplete: held `unavailable`.
4. `authority` newer than this replica, or at or after an unresolved fork: held `authorityBehind`.
5. Epoch not current at that seq: refused `wrongEpoch`.
6. Clock jump: refused `clockJump`.
7. `writes` spent by earlier admitted headers: refused `budgetSpent`.
8. Otherwise admitted; reserves one budget slot per distinct `(author, id)`.

After opening: a kind outside `kinds`, or a failing `conditions` predicate, is refused
`outOfScope` and still reserves its slot. Missing epoch key: held `unavailable`. 0.3 §5's rules
for `invalidPayload`, `duplicateID` and unknown payload versions apply. **In an upgraded
account** a `/3` header is admitted under 0.3 §5 and 0.4 only if it cites authority before the
`upgrade` and its `library` is the legacy ID; a `/5` header cites the `upgrade` seq or later;
anything else is refused `wrongFormat`.

### 11.6 Proposals

A `propose` record is admitted like a write and not folded as one.

- `colophon.accept` and `colophon.decline` have payload `{"proposals":["<operation ID>", …]}`
  (1–64). Each is a `write` record in the proposals' namespace and resolves a proposal only if
  its author may `write` the proposal's kind and **its clock exceeds the proposal's**.
- For each proposal the first valid resolution in fold order wins; later ones are evidence.
- An accepted proposal is folded once, at its accept's position, attributed to the proposer with
  `acceptedBy`; it counts once against the proposer's `writes`, the accept once against the
  accepter's.
- A resolution naming a proposal the reader lacks is held for it.
- **An acceptance is never final:** an earlier-sorting resolution can still arrive. Nothing
  irreversible outside the account may be done on the strength of one.

### 11.7 Basis

`basis` is a reserved payload field: up to 32 `{"claim","ref"}` objects with optional `digest`.
The core checks only its shape.

### 11.8 Incorporated 0.3 sections

Exactly these parts of [colophon-0.3.md](colophon-0.3.md) are normative for 0.5, with the
substitutions below. They are named by their opening words; each runs to the next paragraph
named here or the end of its section. Everything else 0.3 says is replaced by this document.

| 0.3 part | What it governs |
| --- | --- |
| §4, from "Hosts store records and merge them as a set" through "…merge validates the entire proposed authority chain before changing the replica." | Paths, immutability, `state/` and `history/`, read scopes, `budgetScopeUnavailable` |
| §4, "New libraries MUST write a root-signed `layout` …" | Read as: a `/5` account is at layout 2 from genesis and writes no `layout` entry for it; `layout` entries only raise it above 2. Readers stop on an authenticated layout they don't support. |
| §5, "Only authenticated, admissible payloads compete for a same-author operation ID…" | `duplicateID` |
| §5, "A reader missing a historical key…" through "…enforce a globally fresh budget from an incomplete record set." | `invalidPayload`, budget reservation, unknown versions, local action checks |
| §5, "Fold order is `(clock, author, id)`…" through "…ordering tails." and "Clocks are positive integers…" through "…Budget accounting uses the same order across namespaces." | Clocks, live heads, anchoring |
| §5, "An exact copy of a currently authenticated live head…" | The live-head insertion optimization |
| §5.1 | Live playback state and engagement evidence |
| §6 | Domain modules, views, tools and the ledger |
| §7, §7.1, §7.2 | Host contract, verified-prefix cache, import and blobs |
| §8 | The HTTP relay |

Substitutions:

- "library" reads "account"; `libraryID` in a live stamp reads `account` with the 64-hex ID.
- "root-only" and "the root's import role" read "the `import` term". "Reducers receive kind,
  immutable grant and root role" reads "reducers receive the member's request `kind`, its terms
  and whether they contain `import`".
- "member kind" reads the request `kind`. A grant's namespaces and access read its `records`
  entries, each with its own access. `writeBudget` reads `writes`.
- An **uncaveated** writer is one whose terms have no `expires`, `writes`, `kinds` or
  `conditions`. A **caveated** live stamp is one by any other writer.
- `/3` header rules read §11.2–§11.5 for `/5` headers.
- "Revocation … preserves only admitted records whose payload and content-derived ID
  authenticated" applies to §9.5: a kept record whose payload doesn't authenticate is refused
  `invalidPayload`, not preserved.
- §7.1's "exact outer envelope bytes (including signatures)" reads "exact body bytes" (§8.6).
- §8.2's 412 for different bytes at an immutable path reads: different envelope bytes over an
  identical body are identical (200, the first envelope is kept), and only a different body is
  412.
- §8's "await acknowledgement of each authority sequence before uploading its successor" reads:
  a home's acknowledgement of a `POST {base}/authority` batch (§14) acknowledges every entry in
  it.
- Publication and reading of authority history on a relay that is a home read §13–§14.

## 12. Links and calls

### 12.1 Link

```json
{"protocol":"colophon/link/5","account":"<64 hex>","from":"<keyID>","to":{"signing":"<base64>"},
 "session":3,"terms":{"services":[…]},"notBefore":"…","expires":"…","created":"…"}
```

Signed `raw` by `from`'s key: the member for the first link, the previous link's `to` after.
`session` only on the first link. `notBefore` ≤ `expires` ≤ `notBefore` + `policy.linkMaxAge`.

### 12.2 Call

```json
{"protocol":"colophon/call/5","account":"<64 hex>","asOf":{"seq":41,"digest":"<64 hex>"},
 "signer":{"member":"<memberID>"},"key":"<base64>","links":["<base64>"],
 "audience":"https://projects.luff.works","purpose":"task.read","args":{"task":"T-12"},
 "requestId":"<43 chars>","created":"2026-11-11T09:01:00Z"}
```

| Field | Rule |
| --- | --- |
| `asOf` | An entry the signer had seen. |
| `signer` | `{"member":…}` or `{"controller":…}`. |
| `key` | The acting key's signing point. |
| `links` | 1–4 links (the most `depth` allows) from the member outward; absent for the member's own key and always for a controller. |
| `audience`, `purpose` | §10.1 grammar. Purposes starting `colophon.` are reserved (§13.4, §14). |
| `args` | A JSON object, at most 16,384 bytes. |
| `requestId` | 32 random bytes, unpadded base64url. |

Signed `raw` by `key`, or with `assertion` by a WebAuthn controller.

### 12.3 Verifying a call

A verifier MUST, in order:

1. **Parse.** Bounds; `protocol` is `colophon/call/5` (anything else `malformed`); every embedded
   link `colophon/link/5`; fields well formed.
2. **Possession.** The signature verifies under `key` (ES256 over the body, or for an assertion
   `clientData` `type`, `challenge`, `crossOrigin` and §4.3 step 5 under `key`). Else
   `badSignature`. Nothing is fetched before this.
3. **Audience, window, replay.** `audience` is one of the verifier's own (§10.1), else
   `refused:audience`. `created` within 3,600 s of the clock, else `refused:window`. The replay
   store (§12.4) is consulted as it says.
4. **History.** The verifier holds a verified history containing `asOf` (a different digest there
   is `refused:fork`) and fresh heads from at least `policy.headQuorum` distinct current homes,
   and has fetched up to the highest of them. No homes, or too few fresh heads: `unavailable`.
   Let **S** be the highest seq covered by `headQuorum` fresh heads. `created` within
   `policy.callWindow`, else `refused:window`. An unresolved vouched fork: `refused:fork`.
5. **Signer, evaluated at S, with removals beyond S applied.** Grants, controllers and terms added
   after S don't count. Revocations, controller removals, demotions, `endSessions` and policy
   changes that shorten or restrict, held by the verifier after S, apply at once. A pending
   transition changes nothing until its `activate` entry (§8.7). Then:
   - **A controller:**
     - It must be present, not suspended, and not added by an activation that isn't yet final
       (§8.7), else `refused:revoked`.
     - Its roles must include `approve` or `control`; or be `sign` with `audience` in its
       `audiences`; or include `recover` when `purpose` is `colophon.history.read`. Otherwise
       `refused:outOfScope`.
     - Its `signing` must equal `key`, and the assertion must pass all of §4.3 with its
       descriptor, else `badSignature`.
     - The `origin` must be exactly one of the verifier's call-ceremony origins for its `rp`, else
       `refused:origin`.
   - **A member:** it must be present and not revoked, else `refused:revoked`, and not expired,
     else `refused:expired`.
6. **Chain.** Each link verifies under the previous key and has this `account` and `from`, else
   `badSignature`; first link's `session` equals the member's session number, else
   `refused:ended`; `notBefore` ≤ now ≤ `expires` and `expires` within the previous link's and
   the member's, else `refused:expired`; terms narrow, else `refused:notNarrower`. The acting
   `key` equals the last link's `to.signing` (no links: the member's key), else `badSignature`.
7. **Purpose.** For a member, its terms and every link's must allow `audience` and `purpose`, and
   every `conditions` predicate must hold on `args`. For a controller, `purpose` must be among
   the verifier's configured purposes for controller calls; there is no generic or fallback
   purpose. Else `refused:outOfScope`.
8. **Extensions.** Unknown fields, terms or values in the authenticated call, links or terms:
   `newerFormat`.
9. Otherwise `ok`, recorded in the replay store as §12.4 says.

### 12.4 Replay store

- **Key.** `(account, audience, acting key ID, purpose, requestId)`.
- **Reservation.** After step 7 and before any effect, the verifier makes an atomic
  compare-and-swap reservation of the key, recording the body digest:
  - an existing reservation with the same digest is `refused:replay`;
  - one with a different digest is `refused:conflict`.
- **Terminal states.** A reservation ends as exactly one of `completed(result, effect)`,
  `completed(result, none)` or `abandoned`. The effect and its completion MUST commit together,
  or the effect MUST write a durable record (call digest, effect identity, replayable result)
  under the key in its own transaction.
- **Crash recovery.** A reservation left pending is resolved from that record: to completed if the
  effect committed, otherwise to `abandoned`. It is never resolved by re-running the effect.
- **Later identical calls** are `refused:replay`. An audience MAY return the recorded result of a
  non-read purpose to the same acting key.
- **Sharing and retention.** The store is shared by every instance serving the audience and keeps
  reservations for 7,200 s.
- **Rate.** A store MAY rate-limit keys with `refused:window`.
- **Records.** `ok` is not a record in the account. A service that acts on a call writes records
  under its own member key, with a `basis` naming the call's digest.

## 13. Homes and heads

### 13.1 Homes and the primary home

A home is a member with `serves: ["home"]`, appointed by a transition. Any server, device or
service the owner chooses can be one. A home stores only entries, transitions and vetoes that
verify `ok`, and holds no controller or member private key, PRF output or seed. An account appoints
up to 8 homes.

- **Ordering.** Immediate entries go first to the primary home (`policy.primaryHome`, else the
  earliest-appointed current home), which stores the first valid entry per seq. Other homes store
  them once a primary head covers them.
- **Transitions.** Every home receipts transitions and vetoes and appends `activate` and `vetoed`
  entries (§8.7), whatever the primary does. A home stores an `activate` only for a transition it
  receipted itself, or one it first saw at least the delay before, by its own clock.
- **Clock.** A home refuses an entry more than 60 s ahead of its clock, and any `activate` or
  `vetoed` whose determined `issued` is more than 7 days behind it.
- **Rate.** The primary home MUST refuse an immediate entry that would leave more than 64
  immediate entries, or more than 4 MiB of them, with `issued` in the preceding 24 hours by the
  same primary signer, or more than 256 entries or 16 MiB for the account. `activate`, `vetoed`
  and `suspend` entries are exempt. These limits are settings of the home, with these defaults
  as minimums every home accepts.
- **Notices.** On receipting a transition, a veto or a `suspend`, a home MUST push a notice to
  every controller device that has registered a delivery endpoint with it, and MAY send
  out-of-band notices (for example e-mail) the owner configured.
- **First upload.** A genesis may be followed in one upload by the transition appointing a home
  and its `activate` (due when issued, since the state before it has no home).

### 13.2 Head

```json
{"protocol":"colophon/head/5","account":"<64 hex>","authority":{"seq":41,"digest":"<64 hex>"},
 "issued":"2026-11-11T09:00:00Z","by":"<home member ID>"}
```

Signed `raw` by the home's member key. It says only that this home held exactly this verified
history up to `seq` at `issued`.

### 13.3 Verifying and keeping heads

A verifier accepts a head when it parses within bounds; `by` is a current, unexpired home in the
verifier's latest held history and its key verifies the signature (else `badSignature`);
`issued` is at most 60 s ahead of the clock; and the verifier's history, fetched further if
needed, contains `authority.seq` with that digest (a different digest: `refused:fork`; fetch
failure: `unavailable`). A head is **fresh** while `now − issued ≤ policy.headMaxAge`. A head that
is not fresh is never used as evidence of the current state.

- **High-water mark.** A verifier persists per account its highest accepted `(seq, digest)` and
  the folded state there, and accepts later only histories that extend it (`refused:rollback`
  otherwise), moving across a conflict only as §8.6 allows.
- **Incremental verification.** A verifier MAY resume from its persisted state: it fetches entries
  after its high-water seq, checks the first one's `previous` against its persisted digest, and
  verifies each under §8. A verifier with no persisted state MUST fetch and verify the complete
  history from seq 1, in pages; it MUST NOT accept a suffix it can't link to a state it verified.
- **Quorum.** Heads from different homes are compared by ancestry: a lower seq is behind, not
  wrong; divergent histories are a fork.
- **Equivocation.** Two heads by one home with the same `seq` and different digests prove that
  home misbehaved. A verifier holding both MUST keep the evidence object
  `{"protocol":"colophon/equivocation/5","account":…,"heads":["<base64 head envelope>", "<…>"]}`
  (heads sorted by body digest), MUST stop counting that home for this account, and SHOULD send the
  evidence to the account's controllers. Anyone can verify it from the home's key alone.
- **What freshness gives.** With `headQuorum` 1, heads give availability and a bound on how stale
  an honest primary's view can be; a compromised home key can keep signing fresh heads over an
  old history for a verifier that has seen nothing newer. A newer verifier then learns of
  removals only from other sources (devices, other homes). The account bounds this by raising
  `headQuorum` with independently run homes, and by appointing a new primary under the control
  rule (§13.1). A brand-new verifier fetches the history from any source, verifies it from seq 1,
  asks every home the history names, and applies §12.3 step 4.
- A home SHOULD sign a new head at least every `policy.headMaxAge` / 2 and MUST NOT sign a head for
  an entry it hasn't verified.

### 13.4 Who may read the history

`policy.history` `public`: anyone. `members`: callers presenting a valid call with audience a home
endpoint and purpose `colophon.history.read`, signed by a controller holding `approve`, `control`
or `recover`, by a `sign` controller listing that audience, by any current member, or under terms
granting that purpose there. The head is always public. This governs every path serving the
history, transitions, vetoes and receipts, including `records/authority/*` on a relay that is a
home.

### 13.5 Receipt

```json
{"protocol":"colophon/receipt/5","account":"<64 hex>","object":"<body digest>","received":"…","by":"<home member ID>"}
```

Signed `raw` by a home's member key for a transition, a veto or a successor genesis, and stored
beside it as `<home member ID>.receipt.json`. It is valid when:

- `by` is a current home in the state the verifier evaluates;
- `object` is the receipted body's digest;
- `received` is not earlier than that body's `issued` and not more than 300 s after it. For a
  successor genesis, the window instead ends 300 s after the `issued` of the entry that appointed
  the receipting home.

## 14. Exchange

A home is a relay (0.3 §8) whose `GET {base}` response adds `"home":{"member":"<ID>"}`. At
`{base}`:

| Request | Response |
| --- | --- |
| `GET {base}/head` | 200 latest head envelope; 404 if none. Public, `no-store`. |
| `GET {base}/authority?after={seq}&limit={n}` | 200 `{"entries":[…],"receipts":[…],"more":bool}`, 1–64 entries from `after + 1`, under §13.4. |
| `POST {base}/authority` | `{"from":<seq>,"entries":[…],"receipts":[…]}`, 1–64 contiguous entries. 200 `{"head":…,"receipts":[…]}`; 409 with the current head if `from` overlaps different bytes or leaves a gap; 422 with the §1 result; a non-primary home answers 421 with the primary's endpoints for an entry no primary head covers. No other authorization is needed. |

A home that is a successor's home also serves `GET {base}/predecessor/authority/<8 digits>.json`
(and its receipts) for the predecessor's history through its final entry (§15.1). A `PUT` or
`POST` of an envelope whose body equals a stored one answers 200 and keeps the stored envelope
(§2.2, §11.8).

`Authorization: Colophon <base64url of a call envelope>` MAY replace a bearer token, verified under
§12.3 with audience `{base}`: `colophon.home.read` for reading records, allowed as §13.4 allows
history; `colophon.home.write` for writing records, allowed to controllers with `approve` or
`control`, to `sign` controllers listing `{base}`, to members under terms granting it, and to any
member writing only paths under its own author ID. A bearer token remains storage access only.

## 15. Succession and exit

### 15.1 Predecessor

```json
"predecessor":{"format":"colophon/authority/5","account":"<id>","head":{"seq":12,"digest":"<64 hex>"}}
```

`format` is `colophon/authority/5` or `colophon/swift-keyring/2` (§16.3); `account` is 64 hex, or
the 32-hex Swift library ID; `head` is the predecessor's last entry before its final entry F. A 0.4
library upgrades in place instead.

**F.** F is at `head.seq + 1`, with `previous` = `head.digest`, and names this account.
- For `/5` it is the `activate` of a `successor` transition: the waiting and vetoing happen in the
  predecessor (§8.7).
- For Swift it is the freezing `layout` entry (§16.3). Swift has no pending entries, so the
  waiting happens in the successor first:
  1. **Handover.** The genesis carries `handover`: signatures over the genesis body by the keys
     that may write F at `head` under §16.3. For a root library that is the current root; for a
     keyring library, the control threshold, plus `recoverThreshold` recover keys when the
     genesis changes the recover set or lowers that threshold. `handover` MAY carry further keys
     current at `head`.
  2. **Receipts.** Its homes receipt the genesis (§13.5). The succession is due at the
     `headQuorum`-th smallest such `received` plus the successor's `recoveryDelay`.
  3. **Veto window.** Until then, it may be vetoed by keys current at `head`, or current
     immediately before the last predecessor entry that replaced the root or recovery identity or
     removed a controller (so the kit, an old root, or a removed device can object). A veto needs
     as many keys as `handover` has signers.
  4. **Recording.** Successor homes record a valid veto as a `vetoed` entry in the successor's
     history, naming the genesis digest as `transition`.
  5. **Write F.** F is written only after the due time.
  - **Why root alone for a root library:** in the shipping app the root alone can
    `rotateRecovery()`, and the kit alone can `recover()` a new root, so requiring both adds
    friction without stopping either thief. What protects the owner is the veto window, in which
    the kit and the old root can both object.
- **Published** at the predecessor's own homes (`/5`), or at the successor's homes under
  `{base}/predecessor/` (Swift).

**Verified** when:
- the verifier holds the predecessor history through F;
- F names this account;
- the history has no fork at or before F;
- the succession was due before F;
- the successor history through F's due time, as covered by `headQuorum` heads, has no `vetoed`
  entry naming it.

`handover` signatures are authority signatures with the genesis descriptors' origins.

**Competing attempts.** A Swift predecessor's final entry is the first freezing entry whose
succession is verified. A freezing entry whose succession isn't verified (premature, vetoed or
never due) doesn't end the predecessor: the owner may make a new attempt and write a later freezing
entry (a higher layout) after it. A verifier that has persisted a verified succession keeps it.
Any entry after the final entry is `malformed` evidence. Two verified attempts with the same due
time are both `refused:fork`. A predecessor confers nothing: no member, grant or key comes from
it.

### 15.2 Successor

After a `successor` transition activates, the account accepts no further entry; later entries are
`malformed` evidence. The old account stays readable. A verified succession can't be undone.

### 15.3 Clean copy

A copy tool:

1. preflights the whole predecessor with its format's verifier, and stops on any failure;
2. creates the new account (keyring, namespaces, `predecessor`, `handover`), appoints its homes
   and publishes the predecessor;
3. proposes the copying member's `import` grant, to fall due with the succession;
4. writes F only after the succession is due and unvetoed and the person has been told the old
   apps will stop reading the library;
5. copies every record through the **drain window** (a host setting, default 7 days, 0–30), then
   writes the `migration` transition.

It MUST rebuild a slot for every controller that had one, and give every carried value a 0.5 form
(§16.2), or stop and say why. Records arriving after the window stay in the frozen predecessor;
hosts show them as left behind, with an action to copy them.

### 15.4 Migration entry

The `migration` change of a transition (§8.7), at most once per account, only in an account
whose genesis has `predecessor`:

```json
{"migration":{"predecessor":{"format":"…","account":"…","final":{"seq":13,"digest":"<64 hex>"}},":{"format":"…","account":"…","final":{"seq":13,"digest":"<64 hex>"}},
 "drain":{"from":"2026-11-11T08:05:00Z","until":"2026-11-18T08:05:00Z"},
 "namespaces":[{"namespace":"notes","source":120,"copied":118,"omitted":2,"view":"<64 hex>"}],
 "omitted":[{"ref":"<64 hex>","reason":"invalidPayload"}],
 "controllers":[{"id":"<keyID>","slot":true}],
 "members":[{"id":"<memberID>","label":"Taupe on iPhone","kind":"app","outcome":"rejoin"}]}}
```

| Field | Rule |
| --- | --- |
| `drain` | The drain window (§15.3). |
| `namespaces` | Every predecessor namespace. `view` is the SHA-256 of the sorted, newline-joined lowercase hex body digests of the destination records copied into the namespace. |
| `omitted` | Up to 4,096 source records not copied, each by body digest with a reason. More than that: the tool stops. |
| `controllers` | Every predecessor controller, with whether it has a slot here. |
| `members` | Every predecessor member with its mapped kind and `outcome` `rejoin` or `dropped`, with `reason`. |

**It is the owner's assertion, not proof.** It says what the owner's tool copied; no verifier can
check that every old record or key was carried, and none may treat it as proof of completeness.
Any application that moves its own references from the predecessor to this account (for example a
principal binding) MUST still require a verified succession **and** this entry, so that the move
is never made silently.

## 16. Upgrading existing accounts

### 16.1 From 0.4, in place

A 0.4 library becomes a 0.5 account by appending, under the 0.4 control rule:

```json
{"protocol":"colophon/authority/4","seq":9,"previous":"<64 hex>","issued":"…","by":"<controller ID>",
 "kind":"upgrade","account":"<64 hex>","keyring":{…0.5 keyring…}}
```

- A 0.4 reader reports `newerFormat` at it (0.4-keys §6.3) and changes nothing. It is not a
  stop for an app that already holds state: a 0.4 app keeps its in-memory view and can keep
  writing `/3` records citing earlier authority, which 0.5 readers admit (§11.5). Nothing is lost.
- `account` equals SHA-256 hex of the seq-1 body. `keyring` equals the prior keyring in
  `controllers`, `threshold`, `recoverThreshold`, `vault` and `slots` (slots in the same order)
  and adds `addThreshold`, `countBy` and `policy`. Not seq 2; at most once; every later entry `/5`.
  `issued` is not earlier than the previous entry's.
- Members carry over: a 0.4 grant becomes terms `{records: [{namespace, access: "write" if access
  contains "write" else "read"}…], expires, writes: writeBudget, import}`; session numbers start
  at 0. Epochs, seals, slots and `/3` records keep working.

The upgrading host MUST NOT write it until every app writing to the library reads 0.5.

**The `/4` prefix.** An upgraded account's entries up to and including `upgrade` are verified by
[colophon-0.4-keys.md](colophon-0.4-keys.md) §2–§7 exactly as written, which this section
incorporates for that prefix and nothing else. Those rules are the released 0.4 engine's, and the
candidate's upgrade vectors were replayed on it.

### 16.2 From the Swift keyring authority (the shipped apps)

Libraries made by Taupe and Marginalia use §16.3's format. They move by clean copy (§15.3) into a
new account with `predecessor.format` `colophon/swift-keyring/2`, reusing the old controllers'
public keys (same passkeys, security keys, device keys and kit, same key IDs) with roles the
person chooses and `authorityOrigins` on each `webauthn` controller. **No new account at any
service and no new passkey.**
- Each passkey or security key with PRF needs one assertion to build its new `prf` slot; sealed
  slots need none.
- Members rejoin. Swift roles map `device`→`device`, `app`→`app`, `web`→`app`, `agent`→`agent`
  and `service`→`server`.
- `custody` and `keyOperator` map to the request's `custody` and `operator`.
- Caveats: `kinds` maps to `records.kinds`, and `ceiling` to an `lte` condition. A `budget` caveat
  has no 0.5 form, so the tool stops unless the person drops that member.
- A thief who writes a premature or foreign freezing entry stops the old apps. The owner then
  makes a new attempt (§15.1), or, if that can't be verified, an unverified copy.

### 16.3 The Swift keyring format (`colophon/swift-keyring/2`)

This section is normative for verifying a predecessor, in every binding. It describes Marginalia
`packages/Colophon/Sources/ColophonAuthority` at `origin/main` `c8280332`.

**Records.** `authority/<seq, 8 digits>.json` holds a JSON object with `body` and `signature`
(standard base64), optional `assertion` (`{authenticatorData, clientData}`, base64) and optional
`cosignatures` (array of `{signer, signature, assertion?}`). The body is JSON produced by Swift's
`JSONEncoder` with sorted keys, unescaped slashes, ISO 8601 dates without fractions
(`YYYY-MM-DDTHH:MM:SSZ`) and base64 bytes. Verifiers use the exact stored body bytes. The library
ID is the first 32 hex of SHA-256 of entry 1's body; each entry's `previous` is SHA-256 hex of the
preceding body and `seq` is contiguous.

**Body fields.** `seq`, `previous` (absent at 1), `issued`, `kind`, `by`, and by kind: `genesis`
(`label`, `root`, `recovery` as `{signing, agreement}`, optional `controller`, `stewards`,
`threshold`, `layout`); `grant` (`member`, `role`, `custody`, `namespaces`, `write`, `expires`,
`caveats`, `keyOperator`, `label`, `app`, `device`); `revoke` (`memberID`, `kept`); `shareKey`
(`memberID`, `namespace`, `epoch`, `key`); `handover` (`root`); `stewards` (`stewards`,
`threshold`); `rotateRecovery` (`recovery`); `keyring` (`controllers`, `threshold`, `vault`, `slots`,
`signer`, optional `recoverThreshold`); `layout` (`layout`, `signer`). Unknown fields are ignored.
An unknown `kind`, `by` (`root`, `recovery`, `quorum`, `controller`), `role`, `custody`, controller
`kind` (`p256`, `webauthn`), controller role or slot kind makes the history `newerFormat`.

**Controllers.** `{kind, key (65-byte point), rpID?, credential?, label, roles, verification?}`; ID
the first 32 hex of SHA-256 of `key`. A `p256` signature is raw 64-byte ES256 over the body with no
assertion (high-S valid). A `webauthn` signature is §4.3 with `rpID` as `rp`, no `origins`, the
general origin rule, and UV when `verification` or when the rule requires it.

**Historical encodings.** Predecessor signatures use §4.3 step 5 exactly: on macOS 27 CryptoKit
accepts minimal DER and high-S, and refuses every other form tested (candidate `probes/swift-der`).
Duplicate `clientData` members, which Swift's decoder accepted (keeping the first), are refused,
and the preflight stops. iOS and visionOS are unverified until the probe runs there (§21).

**Rules.** Entry 1 is `genesis`, `by: root`, signed by `root`; `layout` absent or 1–2. Before a
keyring is adopted: `by: root` entries are signed by the current root; `by: recovery` only on
`handover`, by the recovery identity; `by: quorum` only on `handover`, by at least `threshold`
distinct stewards; the first `keyring` entry is `by: root`, raw, no cosignatures, and adopts the
keyring. After adoption, only `grant`, `revoke`, `shareKey`, `keyring` and `layout` appear, all
`by: controller` with `signer` the primary controller ID and cosignatures distinct controllers:
`grant` and `revoke` one `approve` signer, no cosignatures; `shareKey` one signer with `approve`,
or with `control` only when sharing to the vault or to a member that already holds that namespace;
`layout` all signers `control`, at least `threshold`, UV; `keyring` either at least `threshold`
`control` signers with UV and, if it lowers `recoverThreshold` (absent = 1), at least the old
`recoverThreshold` `recover` signers too; or only `recover` signers, at least `recoverThreshold`,
with UV, and a change that only adds (controllers identical, thresholds and vault equal, slots a
superset as a multiset; if `recoverThreshold < threshold` additions are approve-only). A keyring is
valid when controllers are distinct valid points, `webauthn` ones have `rpID`, at least one holds
`control`, `1 ≤ threshold ≤ control count`, an explicit `recoverThreshold` is 2 to the recover count
and then `threshold ≥ recoverThreshold`, and slots are complete. `layout` must exceed the current
layout.

**The freezing entry.** F is a `layout` entry with `layout` 3 and an extra field `successor` (the
64-hex 0.5 account ID), signed under the rule in force (root before adoption, the `layout` rule
after). Released Swift readers verify it and then stop with `unsupportedStorageLayout(3)` (those
that predate `layout` stop with `newerAuthority`); they never write after it. A verifier of a
predecessor reads `successor` from F's body.

## 17. Host interface

### 17.1 Authority changes

1. **Unlock first** for any action that reads or seals epochs.
2. **New PRF slots need PRF before the body** (§7.2).
3. **Prepare:** the exact body, which signers satisfy which rules (§8.4), and each challenge.
4. **Finish:** the core verifies §4 and §8 before returning the record; nothing is written on
   failure.
5. **Prompts:** each body needs its own assertion; a hardware `raw` key with an authenticated
   context SHOULD sign every body of one action under one presence check.

### 17.2 Calls, links, heads and verification

The core prepares links, calls, heads, receipts, transitions, vetoes and `suspend` entries as exact
bodies for the host to sign. It verifies calls (§12.3) and heads (§13.3) from inputs the host
supplies.

The **history verifier** needs no host identity. Per account it returns:
- the account ID, the legacy ID and the head;
- per entry, its signers and the rule met;
- per transition, its receipts, due time, vetoes, outcome and finality, plus v(u) for each unit;
- per controller ever present, its descriptor, roles, holder, first and last seq, and any
  suspension;
- per member, its keys, kind, label, custody, operator, terms, grant, renewals, session number and
  revoked seq;
- the homes and the primary, thresholds, `countBy` and policy;
- forks; the predecessor, successor and migration.

It resumes from persisted state. The core also exposes a standalone WebAuthn check returning `ok`
with the UV bit, or `badSignature` with the failed check, and a pure Swift predecessor verifier.
The host alone may open a non-`colophon/` HPKE seal to the vault for its own registered formats
(R10). The core never exports the seed or a raw ECDH output.

### 17.3 Adding a key

**Adding a passkey on a new platform is one approval** at the default `threshold` 1:

1. The new device registers the passkey (UV required, attestation none, `authorityOrigins` set),
   performs one assertion for the PRF slot, and signs the transition body as its possession
   proof.
2. Without the seed, the devices pair and the seed moves (§7.3, §7.4); the new core builds the
   slot.
3. An existing control key signs the transition that adds it with `control`. It activates after
   the delay, or at once when every control key signs. The person may instead add it as
   `approve` only at once (an immediate entry), and then propose `control`.

A host MUST NOT add a controller whose `rp` belongs to a non-production release channel except as
a `sign` controller limited to that channel's audiences.

### 17.4 WebAuthn user handles

`user.id` is a lookup hint. Hosts SHOULD set it to the UTF-8 64-character account ID when the
account exists, and to 32 random bytes otherwise. Verifiers find a controller by `rp` and
`credential` and never require a `user.id`.

### 17.5 Notices

The mechanism is only as safe as people's knowledge of pending transitions, so:

- **Polling.** Every host holding a controller key MUST fetch pending transitions, vetoes and
  suspensions from every current home at launch and at least every `recoveryDelay` / 6.
- **Showing.** It MUST show each one it hasn't shown, with its signers' labels, key IDs and
  first-seen seq, its due time, and a one-tap **veto**.
- **Recovery keys first.** A host that is about to use a recovery key MUST fetch pending
  transitions first. A person whose only device was stolen learns of the thief's transitions the
  next time they use any recovery key with any host.
- **Removal follow-up.** When a controller's removal activates, hosts MUST list every member whose
  grant it signed since that transition's anchor, and offer to revoke them in one action.
- **What to tell people.**
  - When an account is set up with one device, hosts MUST say that a stolen sole device can't
    veto.
  - In every notice, hosts MUST say that the delay protects who controls the account, not data a
    stolen key could already read.
- **Publishing.** Hosts MUST publish entries to the primary home and then every home.
- **Testability.** These are host requirements with observable behaviour, and the conformance plan
  (§21) tests them with a simulated home.

## 18. Policy fields and defaults

A host is a reference implementation of these defaults; another may ship others within the
ranges.

| Field | Default | Range | Changed by |
| --- | --- | --- | --- |
| `threshold` | 1 | 1 … control units | transition (raising: with consent) |
| `recoverThreshold` | 1 when any controller has `recover`, else 0 | 0, or 1 … recover units | transition with consent |
| `addThreshold` | 1 | 1 … `threshold` | transition |
| `countBy` | `keys` (person), `holders` (company) | `keys`, `holders` | transition with consent |
| `policy.recoveryDelay` | 259,200 s (72 h) | 0–2,592,000 s; ≥ 3,600 s with a home | transition with consent |
| `policy.headMaxAge`, `callWindow`, `linkMaxAge` | 300 s, 300 s, 86,400 s | §6.3 | lowering by a key for itself; raising by transition |
| `policy.headQuorum` | 1 | 1–8, at most the homes | transition with consent |
| `policy.history`, `memberRule` | `members`; `single` (person), `control` (company) | §6.3 | tightening immediate; loosening by transition |
| `policy.primaryHome` | absent | a current home | transition with consent |
| Member `expires`, `depth` | 7 days and 1 for `agent`; none and 0 otherwise | §10.1 | approver; `renew` extends |
| Homes | **two, run by different operators (one may be the owner's own machine), before any recovery key** | 0–8 | transition with consent |
| Home rate limits (§13.1) | 64 entries / 4 MiB per signer, 256 / 16 MiB per account, per 24 h | at least those | the home's operator |
| Drain window | 7 days | 0–30 days | the copying host |

**Reference setups:**

| | Person | Company |
| --- | --- | --- |
| Control keys | each device's owner key, and one passkey per platform or password manager, `approve` + `control`; **at least one control key not on the phone** (for example a computer's device key) | each founder's device keys and passkeys, `holder` the founder |
| Recovery keys | two security keys, **`recover` only**, `prf` slot where delivered, **kept apart** | two per founder |
| Other | a kit or device key not tied to any one domain | the same per founder |
| Homes | two, `headQuorum` 1 | three, `headQuorum` 2 |
| Counting | `keys`; thresholds 1, 1, 1 | `holders`; `threshold` and `recoverThreshold` 2 of 3; `memberRule` `control` |

What this protects, plainly:
- **Eventual control of the keyring.**
- **Not** confidentiality of data a stolen key could already read: a recovery key with a slot,
  plus its PIN, reads the vault at once.
- **Not** uninterrupted service while a stolen online key acts during the delay. Suspension
  limits that.

At `headQuorum` 1, one hostile home together with one stolen control or recovery key can still
win, because it can receipt a backdated transition and hide vetoes. Three homes at `headQuorum` 2
close that and keep working with one home down. Two homes at quorum 1 keep working with one down,
but don't close it.

## 19. Results and reasons

| Where | Reasons |
| --- | --- |
| Authority (§8) | `malformed`, `badSignature`, `newerFormat`; held (future `issued`, a transition not yet due); `refused:fork` |
| Slots (§7) | `refused:vaultLocked` |
| Records (§11.5) | refused `notGranted`, `expired`, `revoked`, `wrongEpoch`, `clockJump`, `budgetSpent`, `outOfScope`, `invalidPayload`, `duplicateID`, `wrongFormat`, `budgetScopeUnavailable`; held `revokedBackdated`, `authorityBehind`, `unavailable` |
| Evidence (§8.6, §15.1) | equivocation evidence; `malformed` entries after a final entry |
| Transitions (§8.7) | due, vetoed, activated (provisional or final), void (signer gone, no change, expired, or result breaks §6); `suspend` invalid without a pending removal |
| Calls (§12.3) | `refused:audience`, `refused:window`, `refused:replay`, `refused:conflict`, `refused:fork`, `refused:revoked`, `refused:expired`, `refused:ended`, `refused:notNarrower`, `refused:outOfScope`, `refused:origin`; `unavailable` |
| Heads (§13.3) | `refused:fork`, `refused:rollback`; `unavailable` |
| Succession (§15) | `refused:fork`; unverified claim |

Inside an envelope, any failure verifying an attached signature is `badSignature`, with the failed
check as an optional diagnostic.

## 20. Versions, and what is not in this version

**Versions.** 0.5 accepts exactly these markers: `colophon/authority/5`, `/request/5`, `/link/5`,
`/call/5`, `/head/5`, `/receipt/5`, `/transition/5`, `/veto/5`, `/equivocation/5`, `/operation/5`, the legacy markers of an
upgraded account (`colophon/authority/4` through its `upgrade`, `/3` records citing before it),
`colophon/relay/3`, and `colophon/swift-keyring/2` for predecessors. A verifier MUST NOT read a
0.5 account under 0.4 rules, and MUST NOT accept a `/3` or `/4` object where §11.5 or §16.1 fences
it out. A later version that adds markers will say which 0.5 markers it retires and how an account
opts in by an authority entry; until an account does, 0.5 markers stay valid for it.

**Not in this version** (each a future authenticated extension):

- Accounts as controllers of other accounts; cross-account signatures.
- Guarded state: an authority ordering transitions, claims, spending limits.
- Modules as published WASM, releases, attestations, adoption, layered agreements.
- Records authored by session keys; epoch-key hand-off to sessions.
- `requires` and signed custody or presence evidence.
- Signed history checkpoints.
- Witnesses beyond `headQuorum`; pairwise account identifiers.
- Pre-rotation; proposals into namespaces the proposer can't read.

## 21. Conformance and freeze

0.5 freezes only when all of these are done:

1. **Vectors.** Every vector below is published under `conformance/0.5/`, with exact bytes and
   one named outcome per case.
2. **Two implementations.** Rust and one other language replay them all.
3. **Swift corpus.** A differential corpus shows the §16.3 verifier matches the released Swift
   verifier on macOS, iOS and visionOS.
4. **Dry run.** A read-only preflight passes over a copy of the owner's real library, on his
   device.
5. **Security review.** An independent implementation security review is complete.
6. **Galley.** Galley's identity contract is aligned.
7. **Notices.** The host notice rules (§17.5) pass against a simulated home.

`conformance/0.5/candidate/` holds the vectors built before any implementation; its README lists
them. The rest are plan step V1.

**Required vectors:**
- **Keys, encoding and upgrade:**
  - every 0.4 key case as `/5`;
  - authority origins for entries, transitions and vetoes;
  - controller calls from call and authority origins;
  - non-canonical JSON and base64; malleated envelopes; invalid dates;
  - the 0.4 upgrade with every refusal.
- **Immediate entries:**
  - each §8.4 row accepted, and the same change refused as immediate;
  - tightening another key's authentication refused;
  - `layout` and `migration` as immediate refused;
  - two epochs for one namespace in a `rekey` refused;
  - the rate limit; headroom at 56 controllers and 224 slots.
- **Transitions:**
  - composite removal with a vault change, and slot rebasing at activation;
  - evaluation before `activate`: an anchor before the first home, an anchor at a lower past
    delay, a receipt by a revoked home;
  - due time as the `headQuorum`-th smallest receipt;
  - `signers` not matching the envelope;
  - determined `activate` bytes from two homes;
  - an `activate` that doesn't displace covered entries;
  - veto validity: count, eligibility, UV, origin, quorum, timing;
  - escalation at receipt and before activation, and its reset;
  - the full set (a) and (b), with removed keys counted;
  - suspension: its effect on calls and immediate entries, the veto lifting it, abuse bounds;
  - delta void cases;
  - mutual removal and the tie;
  - finality, and rollback when a veto appears later;
  - every row of changes §H.
- **Conflicts:** evidence; a fork with and without homes; `resolve`; a transition anchored on a
  losing branch.
- **Members and records:**
  - request coverage; pairing; `serves` and import;
  - renew; revoke with `kept` and up to 16 `heads`; `endSessions`;
  - `/5` headers; proposals.
- **Calls:** every §12.3 refusal; replay states (replay, conflict, abandoned); quorum; S.
- **Heads:** valid, stale, non-home, fork, rollback, equivocation.
- **Succession:**
  - `/5` and Swift (root and keyring, WebAuthn, `rotateRecovery`);
  - the genesis receipt window from the appointing entry;
  - the veto window: in time, too few, by a key no longer current, recorded as `vetoed`;
  - a premature freeze followed by a verified attempt;
  - an entry after the final one; two attempts.
- **Seed transfer:** the HPKE label, wrong nonces.

## 22. Review log

| Date | Reviewer | Findings | Resolution |
| --- | --- | --- | --- |
| 2026-11-11 | — | Revision 1 written | — |
| 2026-11-11 | Codex (Daybreak Blue) | 6 High, 5 Medium | Revision 2; changes §G.1 |
| 2026-11-11 | Independent attack review | 6 High, 8 Medium, 8 Low | Revision 2; changes §G.2 |
| 2026-11-11 | Galley contract R-A1–R-A11 | 11 requests | Changes §B |
| 2026-11-11 | Opus, second review of revision 2 | 8 High, 12 Medium, Low notes | Revision 3; changes §G.4 |
| 2026-11-11 | Codex, second review of revision 2 | 3 High, 7 Medium | Revision 3; changes §G.5 |
| 2026-11-12 | Codex, third review of revision 3 | 3 High, 6 Medium, lows | Revision 4; changes §G.7 |
| 2026-11-12 | Opus, third review of revision 3 (partial) | H1–H3, checks | Revision 4; changes §G.7 |
| 2026-11-12 | Opus and Codex, fourth reviews of revision 4 | H1–H10, M1–M11; 5 High, 5 Medium | Revision 5; changes §G.8 |
