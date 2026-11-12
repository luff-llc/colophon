# Colophon 0.5

**Status: final candidate, revision 3, for review, 2026-11-11.** Not frozen, not
implemented, not released, and no version number has been changed anywhere. Revision 2
answered two reviews of revision 1 (152d991); revision 3 answers two reviews of revision 2
(9e90470). The mappings are in [colophon-0.5-changes.md](colophon-0.5-changes.md) §G. It becomes normative only under §21.
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
| Authority body (`/5`) | 1,048,576 |
| Receipt, refusal body | 1,024 |
| Membership request body | 16,384 |
| Link body | 8,192 |
| Call body, including embedded links | 65,536 |
| `args` of a call | 16,384 |
| Head body | 4,096 |
| Equivocation evidence | 2,097,152 |
| Operation header body (including `ciphertext`) | 16,777,216 |
| `clientData` | 8,192 |

Exceeding a bound is `malformed`. A verifier MUST NOT allocate in proportion to a claimed
length before checking it.

**History size.** The format sets no total bound on a history. Every service and verifier MUST
be able to verify, on first contact, a history of at least **65,536 entries and 256 MiB** of
envelopes in total (the **portability floor**), fetched in pages of at most 64 entries (§14). A
service MAY set higher limits, and MUST document its limits on bytes, entries, signatures
verified and elapsed time per account. When it exceeds a limit it answers `unavailable`
(history incomplete), never partial validity. Verification is resumable from the verifier's own
persisted state (§13.3). Hosts MUST warn an account's owner when its history passes half the
floor. An honest person's account grows by entries that people sign, not by sessions or
records, so it stays far below the floor; an account that exceeds it remains valid but may be
refused service by verifiers that hold to the floor.

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

**Authority origins.** A signature on an authority entry, an `additions` item or a `handover`
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
| `label` | 1–200 bytes. Display only. |
| `roles` | Non-empty, sorted, duplicate-free subset of `approve`, `control`, `recover`, `sign`. `sign` appears only alone. |
| `verification` | `webauthn` only. Present only as `true`: every signature needs UV. |
| `holder` | Optional, 1–64 bytes: a label for the person or custody unit that holds the key. Required on every controller when `countBy` is `holders`. |
| `audiences` | Present if and only if roles are `["sign"]`. 1–32 distinct sorted audiences (§10.1 grammar). |
| `until` | Optional date. Present only on a provisional controller (below). |

The controller ID is its key ID. A controller is always a key: an account is never a controller
of another account in 0.5.

| Role | What it can do |
| --- | --- |
| `approve` | Under `policy.memberRule` `single`: admit any member with any `records` or `services` terms, renew any member, revoke any member except a home, end any member's sessions, introduce epochs (single rule). **The control threshold does not protect these.** Under `memberRule` `control` all of them need the control rule. |
| `control` | Change the keyring, layout, policy and homes; make the account's successor; each within the rules of §8.4. |
| `recover` | Add keys when others are lost (recovery rule), and consent to changes of the recovery set. |
| `sign` | Sign calls (§12) at the listed `audiences` only. Never signs an authority entry, never counts toward any rule, never named by a slot. |

**Provisional controllers.** A controller added by the add rule while `addThreshold` is below
`threshold` is provisional: roles exactly `["approve"]`, `until` no later than the adding
entry's `issued` + 30 days, and no slot or part names it. While provisional:

- it may sign calls, and `grant` entries whose terms contain only `services` (no `records`,
  `serves` or `import`), and nothing else;
- its signatures count only on entries issued no later than `until`, and only while every
  controller that signed the entry adding it (its **sponsors**) is still a non-provisional
  controller with `control`;
- there is at most one provisional controller in a keyring at a time;
- `until` can never be extended or added again. A control-rule entry that removes `until`
  **confirms** it, and only then may a slot name it.

**Holders.** `holder` is a label that the keyring's controllers attest, not proof that two
labels are two independent people. `countBy: holders` therefore counts attested labels. Setting
or changing a controller's `holder` needs the control rule (for a `recover` controller, the
recovery-set rule as well), and the key being labelled MUST sign the entry (in `additions`, §4.1)
the first time it gets a holder and every time its holder changes. One key, alone, can't
attest two people.

### 6.2 Keyring

```json
{"controllers":[…],"threshold":1,"recoverThreshold":1,"addThreshold":1,"countBy":"keys",
 "policy":{…},"vault":{"signing":"…","agreement":"…"},"slots":[…]}
```

| Field | Rule |
| --- | --- |
| `controllers` | 1–64, sorted by ID, no duplicates. At least one holds `control`. |
| `countBy` | `keys` or `holders`. Under `holders`, every count in this document (thresholds, signers) counts distinct `holder` values, and every controller has a `holder`. |
| `threshold` | 1 to the number of `control` controllers (or holders). |
| `recoverThreshold` | 0 if no controller holds `recover`; otherwise 1 to the number of `recover` controllers (or holders). |
| `addThreshold` | 1 to `threshold`. |
| `policy` | §6.3. |
| `vault` | The vault's public identity (§7.1). |
| `slots` | 1–256 slots (§7.2). |

### 6.3 Policy

`policy` has exactly these fields (`primaryHome` optional). They bind every verifier of the
account; a verifier MAY be stricter for calls only.

| Field | Meaning | Range |
| --- | --- | --- |
| `callWindow` | Seconds a call's `created` may differ from the verifier's clock (§12.3) | 30–3,600 |
| `headMaxAge` | Seconds a head stays fresh (§13.3) | 30–86,400 |
| `headQuorum` | Distinct homes whose fresh heads or receipts are needed (§12.3, §13.5) | 1–8 |
| `history` | Who a home serves the history to: `members` or `public` (§13.4) | — |
| `linkMaxAge` | Most seconds from a link's `notBefore` to its `expires` | 60–2,592,000 |
| `memberRule` | `single` or `control` (§8.4) | — |
| `primaryHome` | Member ID of the primary home. Absent: the earliest-appointed current home. | a current home |
| `recoveryDelay` | Seconds before a controller added by the recovery rule can sign (§8.4) | 0–2,592,000, and at least 3,600 while the account has a home |

An entry that leaves the account with one or more homes and `recoveryDelay` below 3,600, or with
fewer current homes than `headQuorum` while it has any home, or names as `primaryHome` a member
that is not a current home, is `malformed`.

**Which changes weaken recovery.** Each change in this table needs the recovery-set rule (§8.4)
on top of its own rule. Every other change of these fields needs only the control rule.

| Field | Change that needs the recovery-set rule | Why |
| --- | --- | --- |
| `recoverThreshold` | any change | Lowering weakens recovery; raising can lock out an owner who holds fewer keys |
| `recoveryDelay` | any change | Shortening removes the owner's time to cancel; lengthening delays the owner |
| `countBy` | any change | It changes what counts as a recovery quorum |
| `headQuorum` | any change | It sets how many receipts start a delay |
| `primaryHome` | any change | The primary orders entries and can delay a cancel |
| `headMaxAge` | raising | Staler heads let a removed key act longer |
| `callWindow` | raising | Older calls stay acceptable |
| `linkMaxAge` | raising | Longer sessions outlive a revocation |
| `memberRule` | `control` → `single` | One `approve` key regains member power |
| `history` | `members` → `public` | Disclosure, not recovery; listed so a thief can't publish the history alone |
| `threshold`, `addThreshold` | none: the control rule counts the larger of old and new `threshold` | — |
| Homes (appointing or revoking any home) | any | Homes witness the delay and store cancels |

### 6.4 Warnings

Hosts MUST warn, in words, before writing an entry after which:

- losing any one key (or holder) leaves no control quorum, no recovery quorum where the person
  chose to have one, or no openable slot;
- fewer recovery controllers exist than the person's chosen number, or no recovery controller
  has a slot;
- **the account has a `recover` controller and no home: "Without a home, any one recovery key
  takes control at once. There is no delay and no time to cancel."**;
- only one `recover` controller exists: "If this one recovery key is stolen, nothing can stop
  it after the delay.";
- a company has exactly two holders and `threshold` 2 ("neither of you can be removed without
  the other"), or two holders and `threshold` 1 ("either of you can act alone, including
  removing the other").

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

Every slot has exactly `kind`, `controllers` (IDs of current controllers, none of them `sign`
or provisional), `label` (1–200 bytes) and its kind's fields:

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
session ends. Offered only to a device about to become a non-provisional controller with a slot.

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
| `rekey` | `epochs` (non-empty) | Introduces consecutive epochs. **If the account declares namespaces, seq 2 MUST be a `rekey` introducing epoch 1 for exactly the declared namespaces.** |
| `grant` | `request`, `terms`, `shares` | Admits a new member (§9.2). |
| `renew` | `member`, `expires`, `shares` | Extends a member's expiry (§9.4). |
| `revoke` | `member`, `kept`, `heads`, `epochs` | Ends a member (§9.5). |
| `endSessions` | `member` | Ends every link under a member (§9.6). |
| `keyring` | `keyring`; `shares` plus `epochs` only if the vault changes; optional `attempt` (only `2`, §8.4) | Replaces the keyring wholesale (§8.3). |
| `layout` | `layout` | Raises the storage layout; never lowers it. |
| `resolve` | `discarded` (`{seq, digest}`) | Ends a fork in favour of this branch (§8.6). |
| `migration` | §15.4 | States what a copy carried and what it didn't. At most once, at seq 2 or later. |
| `successor` | `account` (64 hex, not this account) | The account continues in another. **Terminal:** no entry may follow it (§15.2). |

`namespaces` is 0–64 distinct sorted names of lowercase ASCII letters, digits, `.` and `_`, at
most 128 bytes. 0.5 defines layout 2 (0.3 §4).

### 8.3 Keyring transitions

**Vault unchanged:** every existing slot stays (multiset by canonical JSON without `label`);
order and labels MAY change; slots MAY be added; `shares` and `epochs` absent.

**Vault changed:** the new vault is fresh (§3.3); `shares` seal every existing epoch to it;
`epochs` introduce a new epoch in every namespace.

**Rotation is required** when, for a controller that any slot or part in this account's history
has ever named: it is removed; it loses any role; or its `agreement` changes or is removed. It
is also required when any existing slot is deleted or its cryptographic fields change. Removing
or demoting a controller no slot ever named needs no rotation. Changing only `label`,
`verification`, `credential`, `origins`, `authorityOrigins`, `holder`, `until`, `audiences`,
thresholds, `countBy` or `policy` never requires rotation. A properly signed entry that omits a
required rotation is `malformed`.

**Re-adding a removed controller** is allowed: it is the same principal (§3.3 rule 3). Slots
naming it must be new (fresh secrets for the current vault); its historical slots stay history.

### 8.4 Who may sign what

Signers are evaluated against the keyring and member table **before** the entry (genesis:
against its own keyring). Counts are by keys or holders per the prior keyring's `countBy`. A
signature counts only if its controller is not `sign`, not delayed, and not a provisional
controller outside its limits (§6.1).

| Kind | Rule |
| --- | --- |
| `genesis` | Control rule over its keyring; possession; and the predecessor rule if `predecessor` is present (§15.1). |
| `keyring` | Control rule; else add rule; else recovery rule; else cancel rule; else `badSignature`. Then, in every case, possession, the recovery-set rule where §6.3 or the triggers below require it, and the delay rules. |
| `layout`, `migration` | Control rule. |
| `grant`, `renew`, `revoke` | Control rule when `memberRule` is `control`, when the member's terms (granted or existing) contain `import` or `serves`, or when the entry appoints, renews or revokes a home (then also the recovery-set rule); otherwise the single rule, or a provisional signer within §6.1. |
| `rekey` | Control rule when `memberRule` is `control`; otherwise the single rule, or one `control` signer with no cosignatures. |
| `endSessions` | The member rule; or the control rule when `memberRule` is `control`; otherwise the single rule. |
| `resolve` | Control rule and recovery-set rule of the keyring before the fork (§8.6). |
| `successor` | Control rule and recovery-set rule. |
| `upgrade` (`/4`) | 0.4 control rule (§16.1). |
| unknown kind | Control rule. |

**The rules.**

- **Control rule.** Signers holding `control` number at least the **larger** of the prior
  `threshold` and the new keyring's `threshold` (for kinds that set a keyring); every other signer
  holds `recover` and is there for the recovery-set rule, which must then apply; every WebAuthn
  signature has UV.
- **Add rule.** Every signer holds `control`; at least `addThreshold` distinct signers; UV; the
  change only adds; if `addThreshold` < `threshold`, every added controller is provisional (§6.1).
  A `sign` controller may be added under the add rule at any `addThreshold`.
- **Recovery rule.** `recoverThreshold > 0`; every signer holds `recover`; at least
  `recoverThreshold` distinct signers; UV; only adds; if `recoverThreshold < threshold`, every
  added controller has roles exactly `["approve"]`. Controllers it adds are **recovery-added**.
- **Only adds.** Every existing controller is identical by canonical JSON; `threshold`,
  `recoverThreshold`, `addThreshold`, `countBy`, `policy` and `vault` unchanged; every existing
  slot preserved as a multiset by canonical JSON including label; only new controllers, and slots
  naming only new controllers, are added.
- **Recovery-set rule.** When the prior keyring has `recoverThreshold ≥ 1`, an entry meets its
  rule only if it also carries at least the prior `recoverThreshold` distinct `recover` signers of
  the prior keyring, with UV (one signature may count for both rules), whenever it:
  - removes a `recover` controller, removes `recover` from one, or adds a controller with
    `recover`;
  - changes any field of a `recover` controller other than `label` (its key, descriptor,
    `origins`, `authorityOrigins`, `verification` or `holder`);
  - deletes or changes a slot or part naming a `recover` controller;
  - makes a policy change §6.3 lists, or appoints or revokes a home;
  - is `resolve` or `successor`.

  The cancel rule is exempt.
- **Single rule.** Exactly one signer, no cosignatures, holding `approve`.
- **Member rule.** `endSessions` only: `by` equals `member`; signed `raw` by that current member;
  no cosignatures.
- **Possession.** Every controller an entry adds (every genesis controller that isn't a signer,
  and every new controller of a `keyring` entry), and every controller whose `holder` the entry
  sets or changes, MUST sign the body in `additions`. The signature comes from an authority
  origin; a `sign` controller's may come from any origin its descriptor allows. It needs UV if
  the controller has `verification`. Exempt: the `upgrade` entry, and, in a genesis with a
  verified predecessor, controllers whose key was a controller of the predecessor at `head`. A
  carried-over key may be given a new `agreement` point without proof; a slot sealed to a point
  its holder can't open is useless, never dangerous. A missing or failing proof is `badSignature`.

**Recovery timing.**

- **Delay.** A recovery-added controller is **delayed** until **activation**:
  - with a home: the latest `received` among valid receipts (§13.5) of the recovery entry by
    `policy.headQuorum` distinct current homes, plus `recoveryDelay` (doubled for an attempt-2
    entry). Until that many receipts exist, the recovery entry is *held* (`unavailable`) and has
    no effect on any state;
  - **with no home: activation is the entry's own `issued`. There is no delay.** Any one
    recovery key at `recoverThreshold` 1 takes control at once. Hosts MUST warn (§6.4).
  A delayed controller's signature counts for nothing on any entry whose `issued` is before
  activation, and on no call made before activation (§12.3).
- **Cancel rule.** A `keyring` entry signed by exactly one controller that held `control` before
  the recovery entry it cancels and is not itself recovery-added, with UV, that only removes
  controllers still delayed at its own `issued` (with their slots, rotating the vault as §8.3
  requires) and changes nothing else. A still-delayed recovery-added controller can be removed
  **only** by a cancel-rule entry (or by a cancel meeting the counter-recovery below); no other
  rule removes it.
- **Attempt 2.** A recovery-rule `keyring` entry MAY carry `"attempt":2` when the most recent
  recovery-rule entry in the history was undone by a cancel, and at least one of its recover
  signers also signed that cancelled entry. An attempt-2 entry:
  - is delayed by twice `recoveryDelay`;
  - can be cancelled only by a cancel that also carries at least `recoverThreshold` distinct
    `recover` signers not among the attempt-2 entry's own signers (a **counter-recovery**). One
    control key alone can't cancel it;
  - once active, its added controllers can be removed only by an entry that meets the
    recovery-set rule.
- **Full recovery.** A recovery-rule entry signed by **every** current `recover` controller (at
  least two distinct keys, or holders under `countBy: holders`) needs no receipt and has no delay.
  This is the way out when every home is gone or refuses: with all recovery keys, the owner adds a
  control key, which then appoints new homes under the control and recovery-set rules. A person
  who has lost every control key, every home, and any one of their recovery keys has no way to
  regain authority. Their data stays readable through any slot they can still open.
- **The delay protects authority, not data.** A recovery controller with a `prf` or sealed slot
  opens the vault the moment its holder (or a thief who has it and its PIN) uses it; no delay
  applies to reading.

**Who wins.** The reference personal setup (§18) has device keys and passkeys with `control`,
two security keys with `recover` only, `threshold` 1, `recoverThreshold` 1, one home and a 72 h
delay. D is `recoveryDelay`. Here a "thief" holds the keys named; the owner holds every other key.

| Scenario | Outcome at the default setup |
| --- | --- |
| Owner has every key but one, lost (no thief) | Owner removes the lost key under the control rule. Owner wins. |
| Thief holds one control key | Both can act at once under the control rule; the thief can't touch recover keys, homes, the delay or `successor` (recovery-set rule). If the thief removes the owner's control keys first, the owner recovers: attempt 1 (the thief cancels it), then attempt 2, which the thief can't cancel or remove. After D + 2D the owner's new key removes the thief's. **Owner wins within 3D**; the thief can read data and act under the control rule meanwhile. |
| Thief holds one recovery key | The thief's attempt 1 is cancelled by any owner control key. Attempt 2 is cancelled by an owner control key plus the owner's other recovery key. Meanwhile the owner removes the stolen recovery key (control rule plus the other recovery key). **Owner wins.** The thief reads data at once if that key has a slot. |
| Thief holds one control and one recovery key | The thief meets the recovery-set rule with its recovery key and can remove the owner's other recovery key and every owner control key. **Not safe at the default: the first to act wins.** Closed by `recoverThreshold` 2 (then one stolen recovery key meets nothing, and the owner needs both to recover), or `threshold` 2 with keys held apart. |
| Owner has a single recovery key, and a thief steals it | Nobody else can counter-cancel attempt 2. **The thief wins after D + 2D** unless the owner removes it first, which needs a recovery key. Closed by having two recovery keys (the reference default); §6.4 warns. |
| No home, thief holds one recovery key | No delay: **the thief wins at once.** Closed by appointing a home (the reference setup does so before adding any recovery key). |

### 8.5 Verification order

For seq > 1 the verifier MUST, in this order:

1. Bounded generic parse (duplicates refused). Header: `protocol` (as §8.1 allows here), `seq`,
   `previous`, `issued` (format and monotonic); failure is `malformed`. `by` names a controller of
   the prior keyring (or, for `endSessions`, a current member), else `badSignature`. An `issued`
   more than 60 s ahead of the verifier's clock: *held*.
2. Verify every attached signature (§4) against the prior keyring, member table or added
   controllers. Any failure: `badSignature`.
3. Decide the rule (§8.4; unknown kinds use the control rule). Not met: `badSignature`. A
   recovery-rule entry lacking its receipt where one is required: *held*.
4. Only now look for unknown content anywhere in the body. Found: `newerFormat`.
5. Apply the typed schema, bounds and the rules of §6, §8.2, §8.3, §9, §13, §15 and §16. A
   violation: `malformed`.

Genesis follows the same order with its own keyring. No verifier may be stricter or more
lenient than this section for authority entries.

### 8.6 Forks

Entries are **equal** when their body bytes are equal, whatever their envelopes (signatures are
malleable, §2.2). Two **conflicting** entries are valid entries with the same `seq` and
`previous` and different bodies. A verifier classifies a conflict between X and Y as follows:

1. **Equivocation, not a fork.** If X is covered by heads of at least `headQuorum` current homes,
   or by the verifier's high-water mark, and no current home's head covers Y, then Y is
   equivocation evidence against Y's signers. The verifier keeps
   `{"protocol":"colophon/equivocation/5","account":…,"entries":["<base64>","<base64>"]}` (sorted
   by body digest), shows it to the account's controllers, and goes on using X. This covers a key
   that has since been removed signing at an old seq: it can't freeze the account.
2. **Recovery at a non-primary home.** If X is covered by the primary home and Y is a
   recovery-rule or cancel-rule entry covered only by other homes, X stands and Y is evidence. The
   recovering device signs Y again at the next seq on X's history, and every home stores it
   (§13.1).
3. **A vouched fork.** If current homes' heads cover both X and Y (and rule 2 doesn't apply), the
   verifier MUST answer `refused:fork` for every call, grant check, head and succession that
   depends on either branch, until a `resolve` entry settles it. `resolve` is on one branch, at any
   later seq. Its `discarded` names the other branch's entry (`seq`, body digest). It is signed
   under the control rule and the recovery-set rule of the keyring before the fork. A valid
   `resolve` makes its branch the history; two `resolve` entries on both branches leave the fork
   unresolved.
4. **No coverage** (an account without homes, or entries no home has seen). The verifier keeps the
   entry whose signers meet the strongest rule, in this order: control rule with recovery-set
   rule; control rule; cancel rule; recovery rule; add rule; single or member rule. A tie goes to
   the lower body digest. The other is evidence. A narrow-role key therefore can never displace a
   control-rule entry, and nobody can freeze the account. An account without homes has no
   protection against a removed key rewriting history for a verifier that has seen neither
   branch; persisted high-water marks protect every verifier that has.

A verifier's high-water mark (§13.3) moves to another branch only through rule 2, rule 4 or a
valid `resolve`. Records citing a seq at or after an unresolved vouched fork are held until it is
resolved, then admitted against the resolving branch.

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
   changes that shorten or restrict, held by the verifier after S, apply at once. A held recovery
   entry that isn't yet active changes nothing. Then:
   - **A controller:**
     - It must be present, else `refused:revoked`.
     - It must be neither delayed nor a provisional controller past its `until` or without its
       sponsors (§6.1, §8.4), at the verifier's clock, else `refused:revoked`.
     - Its roles must include `approve` or `control`, or be `sign` with `audience` in its
       `audiences`, else `refused:outOfScope`.
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
- **Reservation.** After step 2, the verifier makes an atomic compare-and-swap reservation of the
  key with state `pending` and the body digest. If a reservation exists:
  - with the same body digest, the call is `refused:replay` and performs nothing;
  - with a different body digest, `refused:conflict`.
- **Completion.** The protected effect MUST either commit in the same transaction that sets the
  reservation to `completed` with its result, or be idempotent under the reservation key. A
  `pending` reservation found after a crash MUST NOT cause the effect to run again
  independently; the service completes or abandons it under its own recovery procedure.
- **Sharing.** The store MUST be shared by every instance that serves the audience.
- **Retention.** Reservations are kept 7,200 seconds regardless of current policy; step 3 refuses
  anything older.
- **Results of replays.** An audience MAY return the recorded result of a completed, non-read
  purpose to the same acting key. For purposes it declares read-only it returns nothing.
- **Rate.** A store MAY refuse a key that exceeds a rate it sets, with `refused:window`.
- **Records.** `ok` is not a record in the account. A service that acts on a call and writes
  records does so under its own member key, with a `basis` naming the call's body digest.

## 13. Homes and heads

### 13.1 Homes and the primary home

A home is a member with `serves: ["home"]`, appointed by a grant under the control and
recovery-set rules. Any server, device or service the owner chooses can be one; the format
assumes no particular operator. A home keeps the history exactly as signed, verifies every
entry under §8 before storing it, and stores no entry that doesn't extend its history. It holds
no controller or member private key, PRF output or seed. An account appoints up to 8 homes.

- **The primary home orders.** Every authority entry is first published to the primary home
  (`policy.primaryHome`, else the earliest-appointed current home). The primary stores the first
  valid entry for each seq and answers later candidates with a conflict (§14). Devices hold
  their entries locally until the primary accepts them.
- **Other homes store only entries covered by a primary head,** with two exceptions:
  - any home MAY store an entry that changes `primaryHome` or revokes the primary, and the
    entries after it once the new primary's head covers them;
  - **every current home MUST store and receipt a valid recovery-rule or cancel-rule entry that
    extends that home's own latest history**, without primary coverage. A primary therefore
    can't block recovery or a cancel by refusing it. Conflicts with the primary's history follow
    §8.6 rule 2.
- **Clock rules.** A home MUST refuse an entry whose `issued` is more than 60 s ahead of its
  clock. It MUST refuse a recovery-rule or cancel-rule entry whose `issued` differs from its clock
  by more than 300 s in either direction.
- **Receipts and notices.** On storing a recovery-rule or cancel-rule entry a home signs its
  receipt (§13.5) and MUST notify the account's controllers (§17.5).
- **First upload.** A genesis may be followed in one upload by the entries that appoint a home; a
  home verifies the batch and stores it only if its own appointment is in it.
- **Reaching other homes.** A device MUST publish every recovery-rule and cancel-rule entry to
  every current home it can reach.

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
endpoint and purpose `colophon.history.read`, signed by a controller with `approve` or `control`,
by a `sign` controller listing that audience, by any current member, or under terms granting that
purpose there. The head is always public. This governs every path that serves the history,
including `records/authority/*` on a relay that is also a home.

### 13.5 Receipt

```json
{"protocol":"colophon/receipt/5","account":"<64 hex>","entry":{"seq":42,"digest":"<64 hex>"},
 "received":"2026-11-11T09:00:03Z","by":"<home member ID>"}
```

Signed `raw` by a current home's member key, stored at
`authority/<8 digits>.<home member ID>.receipt.json`, one file per signing home. A receipt is
valid when:

- `by` is a current home at the prior entry;
- `entry` matches the entry's body digest;
- `received` is not earlier than the entry's `issued` and not more than 300 s after it.

A recovery takes effect only when receipts by `policy.headQuorum` distinct current homes exist.
Its delay runs from the **latest** `received` among them (§8.4), so one colluding home can't
start the clock early. A receipt that predates `issued`, comes too late, or is signed by a
non-home is `malformed`. Adding homes without raising `headQuorum` doesn't change how many homes
must agree.

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

| Field | Rule |
| --- | --- |
| `format` | `colophon/authority/5` or `colophon/swift-keyring/2` (§16.3). A 0.4 library upgrades in place (§16.1) and is never a predecessor. |
| `account` | 64 hex for `/5`; the 32-hex library ID for Swift. |
| `head` | The predecessor's last entry **before** its final entry: `seq` and body digest. |

The predecessor's **final entry** F is at `head.seq + 1`, with `previous` equal to `head.digest`.
A genesis can't name F's digest, because F names the genesis's own digest; this one-entry offset
is how the two commit to each other.

**Where the predecessor is published.**

- For a `/5` predecessor: its own homes. F MUST be covered by fresh heads of the predecessor's
  `headQuorum` current homes.
- For a Swift predecessor: the successor's homes. Each MUST serve the predecessor's history
  through F at `{base}/predecessor/authority/<8 digits>.json` (with the Swift file name and
  bytes) before it stores the successor's genesis. Each successor home receipts F there (a
  receipt whose `entry` names F's seq and body digest and whose `account` is the predecessor's
  ID).
- Verifiers look in these places and nowhere else for competing entries. Uniqueness means
  uniqueness among what those homes serve. It is no stronger than those homes, and with
  `headQuorum` 1, one compromised home can show two verifiers two histories.

**Verified.** A succession is verified only when all of these hold:

1. The verifier has verified the predecessor's history through F under its format, as published
   above.
2. F names this account. For `/5`, F is `successor` with `account` equal to this account's ID.
   For Swift, F is the freezing `layout` entry of §16.3 whose `successor` equals this ID.
3. The published history has no fork at or before F.
4. **Recovery consent.** If the genesis keyring's set of `recover` keys (or holders) differs from
   the predecessor's at `head`, or its `recoverThreshold` is lower, `handover` carries at least
   the predecessor's `recoverThreshold` distinct signers holding `recover` at `head`, with UV.
   Swift: an absent `recoverThreshold` means 1.
5. **Swift root libraries** (no adopted keyring at `head`). `handover` carries `raw` signatures
   by the current root and the current recovery identity. If the history contains any
   `handover`, `rotateRecovery` or `stewards` entry, it also carries signatures by the root and
   recovery identity named in the genesis. A single key of either kind can never move a root
   library. An owner who has lost an original identity can still copy the library, but the
   succession stays an unverified claim.
6. **Recovery-added signers.** If any signer of F or `handover` was recovery-added in the
   predecessor, the succession is verified only after the successor's activation (§8.4: receipts
   by the successor's `headQuorum` homes of the successor genesis, plus its `recoveryDelay`).
   Swift: a controller first appearing in a `keyring` entry that only `recover` signers signed.
   Until then, any predecessor `control` controller that is not recovery-added MAY sign a
   **refusal**, `{"protocol":"colophon/refusal/5","predecessor":…,"successor":…,"issued":…,"by":"<keyID>"}` signed `raw` or with an assertion by that controller,
   delivered to the successor's homes. A valid refusal makes the succession unverified for good.

`handover` signatures are over the genesis body, by §4.3, with the **genesis** descriptor's
authority origins for carried-over keys.

**After verification.**

- A verifier that has persisted a verified succession keeps it.
- Any entry after F, or a second final entry at F's seq, is `malformed` evidence, shown to the
  successor's controllers. It never undoes a succession that was verified and persisted.
- A verifier seeing both for the first time verifies the succession whose F is covered by
  receipts of the successor's homes (Swift) or by the predecessor's home heads (`/5`). If both
  are, both are `refused:fork`.

A verifier that can't establish 1–6 still verifies the genesis under its own rules and reports
the predecessor as an unverified claim. A predecessor confers nothing: no member, grant or key
comes from it.

### 15.2 Successor

`successor` is terminal. Any entry after a valid `successor` is `malformed` evidence, never a fork
and never a reason to doubt the succession (§15.1). The old account stays readable. Freezing is
irreversible: a `successor` or a Swift F can't be undone, and a person who wants the old account
back must make a new succession.

### 15.3 Clean copy

A copy tool moves records into a new account. In order:

1. **Preflight.** Read the whole predecessor with its format's verifier (for Swift, §16.3).
   Stop if any entry fails. Nothing is written before this passes.
2. **Create the new account:** the owner's keyring, the same namespaces, `predecessor` and
   `handover`. Appoint at least one home and publish the predecessor where §15.1 says.
3. **Write F,** after the new account verifies at a home and the person has been told that the
   old apps will stop reading the old library.
4. **Drain.** Keep reading the predecessor for the **drain window** (a host setting; default 7
   days, range 0–30 days). Copy every record that appears, including records written by devices
   that hadn't yet seen F.
5. **Copy and record.** Grant the copying member `write` and `import` with an expiry after the
   window. Publish `colophon.importBatch` units (0.3 §7.2), with source IDs and body digests as
   encrypted evidence. When the window ends, write the `migration` entry.

Further rules:

- The tool MUST rebuild a slot for every controller that had one, or stop.
- It MUST give every carried value a 0.5 form (§16.2), or stop and say which value has none. It
  never drops a value silently.
- Records that arrive after the window stay in the frozen predecessor. Hosts MUST show them as
  left behind, with an action to copy them.
- A reader who isn't a controller may copy what it can open, with no `predecessor` or
  `handover`.

### 15.4 Migration entry

```json
{"kind":"migration","predecessor":{"format":"…","account":"…","final":{"seq":13,"digest":"<64 hex>"}},
 "drain":{"from":"2026-11-11T08:05:00Z","until":"2026-11-18T08:05:00Z"},
 "namespaces":[{"namespace":"notes","source":120,"copied":118,"omitted":2,"view":"<64 hex>"}],
 "omitted":[{"ref":"<64 hex>","reason":"invalidPayload"}],
 "controllers":[{"id":"<keyID>","slot":true}],
 "members":[{"id":"<memberID>","label":"Taupe on iPhone","kind":"app","outcome":"rejoin"}]}
```

Signed under the control rule; at most once.

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

Libraries made by Taupe and Marginalia use the format of §16.3, not 0.4. They move by clean copy
(§15.3) into a new 0.5 account with `predecessor.format` `colophon/swift-keyring/2`:

1. **Preflight** the whole library under §16.3 (§15.3 step 1).
2. **Build the new genesis.** Its keyring reuses the old controllers' public keys (same passkeys,
   security keys, device keys and kit, same key IDs), with roles the person chooses and
   `authorityOrigins` on each `webauthn` controller. Its recover set and `recoverThreshold` stay as
   they were unless the old recovery quorum signs `handover` (§15.1 rule 4). **No new account at
   any service and no new passkey.**
3. **Sign the hand-over.** The old control quorum (and, for a root library, the identities of
   §15.1 rule 5) signs `handover` where §15.1 requires it.
4. **Appoint a home** and publish the predecessor there (§15.1).
5. **Write the freezing entry F** (§16.3), naming the new ID. Every released Swift reader stops at
   it. **This can't be undone.**
6. **Rebuild slots.** One assertion per passkey or security key with PRF builds its new `prf`
   slot. Sealed slots for device keys and the kit need none. Every controller that had a slot gets
   one, or the copy stops.
7. **Drain, copy and record** (§15.3).
8. **Members rejoin.** Swift roles map as follows:
   - `device`→`device`, `app`→`app`, `web`→`app`, `agent`→`agent`, `service`→`server`;
   - `custody` and `keyOperator` map to the request's `custody` and `operator`;
   - grant caveats: `kinds` maps to `records.kinds`, and `ceiling` to an `lte` condition. A
     `budget` caveat has no 0.5 form, so the tool stops unless the person marks that member
     `dropped`.

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

**Historical encodings.** For predecessor entries only, a verifier accepts exactly what the
released Swift verifier (CryptoKit `ECDSASignature(derRepresentation:)`) accepted. On macOS 27,
observed by the probe recorded in the candidate README: minimal DER, and high-S, are accepted;
non-minimal integers, long-form lengths and trailing bytes are refused; **an integer whose first
byte is 0x80 or more with no leading 0x00 is accepted and read as unsigned**. §4.3 step 5 refuses
that last form, and §16.3 accepts it for predecessor entries. `clientData` with a duplicate member
was accepted by Swift's `JSONDecoder`, which read the **first** occurrence. A §16.3 verifier
refuses it instead (§2.3) and the preflight stops: no authenticator emits duplicates, and
accepting first-wins JSON would make the verifier depend on one platform's decoder. iOS and
visionOS behaviour was not probed; the dry run (§21) is the check.

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

**Recovery-added Swift controllers** (§15.1 rule 6) are those first appearing in a `keyring`
entry whose signers all hold `recover` and that `verifyKeyringChange` admitted by its recovery
path (`admitsRecovery`).

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

- The core prepares links, calls, heads and receipts as exact bodies for the host to sign, and
  verifies calls (§12.3) given the history, heads, clock, configured audiences, call-ceremony
  origins, controller-call purposes and replay store, and heads (§13.3) given persisted state.
- **History verifier,** needing no host identity: returns the account ID (and legacy ID); head;
  for each entry, its primary signer, cosigners, possession signers, `handover` signers, the rule
  met and any receipt; each controller ever present with descriptor, roles, holder, first and last
  seq, recovery-added, delayed-until and provisional-until; each member with keys, kind, label,
  custody, operator, terms in force, grant `{seq, digest}`, renewals, session number and revoked
  seq; homes with keys, endpoints and the primary; thresholds, `countBy`, policy; forks and
  resolutions; predecessor (verified or claimed), successor and migration. It may resume from
  persisted state (§13.3).
- **WebAuthn check** (descriptor, body, signature, authenticator data, client data, UV required,
  authority or call): `ok` with the UV bit, or `badSignature` with the failed check.
- **Swift predecessor verifier** (§16.3) in every binding, as a pure function of the stored bytes.
- **Vault seals for other formats.** Only the host application holding an unlocked session MAY
  ask the core to open an HPKE (§11.1 suite) seal `{enc (65 bytes), ciphertext (at most 1 MiB +
  16)}` to the vault's agreement key, with `info` that does not begin with `colophon/` and begins
  with a prefix the host's own configuration registered, and AAD of at most 4,096 bytes. The core
  never exports the seed or a raw ECDH output of the vault key. A member, agent or remote caller
  can never invoke it.

### 17.3 Adding a key

**Adding a passkey on a new platform is one approval by an existing controller** at the default
`addThreshold` 1 with `threshold` 1:

1. The new device registers the passkey (UV required, attestation none, `authorityOrigins` set),
   performs one assertion for the PRF slot, and signs the entry body as its possession proof.
2. Without the seed, the devices pair and the seed moves (§7.3, §7.4); the new core builds the slot.
3. An existing controller signs the `keyring` entry under the add rule.

With `threshold` above `addThreshold`, the new key is provisional (approve only, no slot) until a
control-rule entry confirms it. A host MUST NOT add a controller whose `rp` belongs to a
non-production release channel except as a `sign` controller limited to that channel's
audiences.

### 17.4 WebAuthn user handles

`user.id` is a lookup hint. Hosts SHOULD set it to the UTF-8 64-character account ID when the
account exists, and to 32 random bytes otherwise. Verifiers find a controller by `rp` and
`credential` and never require a `user.id`.

### 17.5 Notices

Every entry under the add, recovery or cancel rule, every controller removal or demotion, every
receipt, every attempt-2 recovery, every `successor`, `resolve`, refusal and policy change, every
succession naming this account as predecessor or successor, and every fork or equivocation a host
learns of MUST be shown on every other device that holds a controller of the account, with who
signed it, when, and *That was me* / *Remove it*. A host MUST publish authority entries to the
primary home, then to every home, and SHOULD NOT tell the person a removal is done until
`n − headQuorum + 1` of the `n` homes hold it. The notice of a recovery says plainly that the
delay protects who controls the account, not the data: a recovery key with a slot has already
been able to read it.

## 18. Policy fields and defaults

Colophon fixes the field, range, default and who may change it. A host is a reference
implementation of these defaults; another may ship others within the ranges. §6.3 classifies
which changes need the recovery-set rule.

| Field | Default | Range | Changed by |
| --- | --- | --- | --- |
| `threshold` | 1 | 1 … control keys or holders | control rule (larger of old and new) |
| `recoverThreshold` | 1 (any one recovery key) when any controller has `recover`, else 0 | 0, or 1 … recover keys or holders | control + recovery-set rules |
| `addThreshold` | 1 | 1 … `threshold` | control rule |
| `countBy` | `keys` (person), `holders` (company) | `keys`, `holders` | control + recovery-set rules |
| `policy.recoveryDelay` | 259,200 s (72 h) | 0–2,592,000 s; at least 3,600 s while the account has a home | control + recovery-set rules |
| `policy.headMaxAge` | 300 s | 30–86,400 s | control rule; raising also recovery-set |
| `policy.headQuorum` | 1 | 1–8, at most the number of homes | control + recovery-set rules |
| `policy.callWindow` | 300 s | 30–3,600 s | control rule; raising also recovery-set |
| `policy.linkMaxAge` | 86,400 s | 60–2,592,000 s | control rule; raising also recovery-set |
| `policy.history` | `members` | `members`, `public` | control rule; to `public` also recovery-set |
| `policy.memberRule` | `single` (person), `control` (company) | `single`, `control` | control rule; to `single` also recovery-set |
| `policy.primaryHome` | absent (earliest home) | a current home | control + recovery-set rules |
| `authorityOrigins` | set at registration (§4.3) | §3.1 | control rule; for `recover` keys also recovery-set |
| `verification` | `true` on every `webauthn` controller | present or absent | control rule; for `recover` keys also recovery-set |
| Member `expires` | 7 days for `agent`; none for `device`, `app` | any, or absent | approver at grant; `renew` extends |
| Member `depth` | 1 for `agent`, else 0 | 0–4 | approver at grant |
| Homes | **one, appointed before any `recover` controller is added** | 0–8 | control + recovery-set rules |
| Drain window (§15.3) | 7 days | 0–30 days | the copying host, per copy |

**The delay needs a home.** With no home, `recoveryDelay` has no effect and recovery is immediate
(§8.4). The reference setup therefore appoints a home, of the owner's choosing, before it adds
any `recover` controller at `recoverThreshold` 1. With a home, the delay is never below an hour.

**Reference setups** (host defaults):

| | Person | Company |
| --- | --- | --- |
| Device owner keys | `approve`, `control`; sealed slot | one per founder device, `approve`, `control`, `holder` the founder |
| Passkeys | one per platform or password manager, `approve`, `control`, `prf` slot when PRF works | each founder's, `approve`, `control`, `holder` |
| Security keys | two, **`recover` only**, each with a `prf` slot where delivered | two per founder, `recover` only, `holder` |
| Rp-independent key | a kit or device key, so no one domain holds every way in | the same per founder |
| Homes | one, before any security key is added | at least two, `headQuorum` 2 |
| Counting | `countBy` `keys`; thresholds 1, 1, 1 | `countBy` `holders`; `threshold` and `recoverThreshold` a majority of holders (2 of 3); `addThreshold` 1; `memberRule` `control` |

Security keys carry `recover` only. With `approve` too, a stolen key could admit an attacker's
member at once, which the delay doesn't cover. A security key's `prf` slot lets it restore data
when every device is lost. It also means anyone who holds the key and its PIN can read the vault
at once. Hosts MUST say so, and offer a combined slot (key and kit together) instead for people
who want that exposure closed.

A company of two holders can't avoid both risks: with `threshold` 2 neither founder can be removed
without signing, and with 1 either can remove the other. Three holders with two to act avoid both:
a departing or refusing holder is removed by the other two (with vault rotation), and no one can
act alone. Hosts warn (§6.4).

## 19. Results and reasons

| Where | Reasons |
| --- | --- |
| Authority (§8) | `malformed`, `badSignature`, `newerFormat`; held (future `issued`, missing receipt); `refused:fork` |
| Slots (§7) | `refused:vaultLocked` |
| Records (§11.5) | refused `notGranted`, `expired`, `revoked`, `wrongEpoch`, `clockJump`, `budgetSpent`, `outOfScope`, `invalidPayload`, `duplicateID`, `wrongFormat`, `budgetScopeUnavailable`; held `revokedBackdated`, `authorityBehind`, `unavailable` |
| Evidence (§8.6, §15.1) | equivocation evidence; `malformed` entries after a final entry; refusals |
| Calls (§12.3) | `refused:audience`, `refused:window`, `refused:replay`, `refused:conflict`, `refused:fork`, `refused:revoked`, `refused:expired`, `refused:ended`, `refused:notNarrower`, `refused:outOfScope`, `refused:origin`; `unavailable` |
| Heads (§13.3) | `refused:fork`, `refused:rollback`; `unavailable` |
| Succession (§15) | `refused:fork`; unverified claim |

Inside an envelope, any failure verifying an attached signature is `badSignature`, with the failed
check as an optional diagnostic.

## 20. Versions, and what is not in this version

**Versions.** 0.5 accepts exactly these markers: `colophon/authority/5`, `/request/5`, `/link/5`,
`/call/5`, `/head/5`, `/receipt/5`, `/refusal/5`, `/equivocation/5`, `/operation/5`, the legacy markers of an
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

0.5 freezes only when **all** of these are done:

1. **Vectors.** Every vector below is published under `conformance/0.5/`, with exact bytes,
   intermediates and one named outcome per refuse case.
2. **Two implementations.** One in Rust and one in another language replay them all.
3. **Swift corpus.** A differential corpus shows the §16.3 verifier accepts and refuses every
   historical Swift signature form exactly as the released Swift verifier does.
4. **Dry run.** A read-only §16.3 run (preflight only, no F) over a copy of the owner's real
   library, on his device, passes.
5. **Security review.** An independent implementation security review is complete.
6. **Galley.** Galley's identity contract is aligned with this text.

`conformance/0.5/candidate/` holds the vectors produced before any implementation; its README
lists which exist. The rest are step V1 of the implementation plan.

**Required vectors:**

- **Keys and signatures:**
  - every 0.4 key case as `/5`, with synthetic WebAuthn;
  - authority origins with and without `authorityOrigins`;
  - controller calls from a call origin and from an authority origin;
  - non-canonical JSON and base64 refused;
  - a malleated envelope (same body) treated as equal;
  - dates (an invalid day, two fraction digits).
- **Upgrade:**
  - accepted, and 0.4's `newerFormat` on it;
  - every refusal;
  - `/3` records cited before and after the upgrade;
  - `/5` before the upgrade.
- **Keyring rules:**
  - control rule with a lower and a higher new threshold;
  - add rule at `threshold` 1 (full) and 2 (provisional);
  - provisional key: after `until`, without its sponsor, a second one, a slot naming it, a
    records grant by it, its call;
  - possession missing and wrong, and holder labelling with and without the key's signature;
  - recovery rule;
  - each recovery-set trigger, with and without recover signers;
  - receipts: quorum, the latest one counts, late, early, non-home;
  - cancel during and after the delay; attempt 2 and counter-recovery; removal of a delayed key
    by the control rule (refused);
  - full recovery without receipts;
  - delayed signer before and after activation, including its call;
  - `countBy` holders;
  - `sign` controller signing authority;
  - re-adding a removed controller with a new slot;
  - removing a never-slotted controller without rotation;
  - slots and rotation for every trigger;
  - principals across time;
  - monotonic `issued`;
  - policy ranges.
- **Forks:**
  - equivocation by a removed key;
  - recovery at a non-primary home;
  - a vouched fork with `resolve`, without the recovery-set rule, and two resolves;
  - no-home priority;
  - high-water mark across a fork.
- **Members and records:**
  - request coverage; pairing commitments and codes;
  - `serves` and import rules;
  - renew forward and backward;
  - revoke with `kept` and up to 16 `heads`: a walk through a refused header, a missing
    intermediate, a fork, a kept record with an invalid payload;
  - `endSessions` three ways;
  - `/5` headers and AAD;
  - proposals in each order.
- **Calls:**
  - every §12.3 step's refusal;
  - replay identical, conflicting and pending;
  - quorum 2 with one stale;
  - additions after S ignored, removals after S applied.
- **Heads and receipts:** valid, stale, non-home, fork, rollback, equivocation evidence.
- **Succession:**
  - `/5` and Swift predecessors (root and keyring libraries, with WebAuthn controllers);
  - `rotateRecovery`;
  - stale head; an entry after F; two final entries;
  - recover-set change with and without consent;
  - a recovery-added signer, and a refusal;
  - persistence after a later rival;
  - migration entry required for principal moves.
- **Seed transfer:** HPKE under the transfer label; wrong nonces.

## 22. Review log

| Date | Reviewer | Findings | Resolution |
| --- | --- | --- | --- |
| 2026-11-11 | — | Revision 1 written | — |
| 2026-11-11 | Codex (Daybreak Blue) | 6 High, 5 Medium | Revision 2; changes §G.1 |
| 2026-11-11 | Independent attack review | 6 High, 8 Medium, 8 Low | Revision 2; changes §G.2 |
| 2026-11-11 | Galley contract R-A1–R-A11 | 11 requests | Changes §B |
| 2026-11-11 | Opus, second review of revision 2 | 8 High, 12 Medium, Low notes | Revision 3; changes §G.4 |
| 2026-11-11 | Codex, second review of revision 2 | 3 High, 7 Medium | Revision 3; changes §G.5 |
