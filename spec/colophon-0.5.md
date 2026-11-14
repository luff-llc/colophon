# Colophon 0.5

**Status: final candidate, revision 13, for review, 2026-11-14.** Not frozen, not
implemented, not released, and no version number has been changed anywhere. Revision 2
answered two reviews of revision 1 (152d991); revision 3 answered two reviews of revision 2
(9e90470); revision 4 replaced every recovery special case with one mechanism, pending
transitions with veto (§8.7); revision 5 answers two reviews of revision 4 (4032d44) by finishing
that mechanism's state model; revision 6 answers two reviews of revision 5 (a1decc6) and the
first engine builder's questions, making that state model checkable by every verifier;
revision 7 answers two reviews of revision 6 (281e7c4) and the engine attack, recording finality
in the history and stating §8.7 as a state table; revision 8 answers the second review of revision 7
(0a25988): removals, revoked homes, recovery that restores control, and verdicts that depend on
the object set only; revision 9 keeps a revoked home current until its revocation is final; revision 10 states the
one-recovery-key stall and narrows the liveness claim; revision 11 states recovery conditions in
units; revision 12 answers the engine check of the 0.5 history verifier and its own check: one
meaning of "final", final successions, possession under handover, the proposer cap, the chain
bound and the Swift steward threshold; revision 13 answers the checks of the write side (the
authority builders, the vault, slots and pairing, the homes and calls): resolving a fork,
per-home head rollback, determined veto receipts and `final` heads, a late veto at a home,
two heads for one seq, the §7.2 slot shape at replay, equivocation evidence, and the text
gaps the builders found (notices, link `created`, the kit derivation, the restricted open, the
PRF assertion, the QR bytes, the seed guarantee). The
mappings are in [colophon-0.5-changes.md](colophon-0.5-changes.md) §G. It becomes normative only under §21.
The work to implement it is [colophon-0.5-implementation.md](colophon-0.5-implementation.md).
Rationale, host wording and the review log are in the non-normative
[colophon-0.5-guide.md](colophon-0.5-guide.md).

**What it replaces.** This document is complete for every identity, authority, grant, call,
head and record-header format it names. It replaces [colophon-0.4.md](colophon-0.4.md),
[colophon-0.4-keys.md](colophon-0.4-keys.md) and every part of
[colophon-0.3.md](colophon-0.3.md) that those kept, except the engine and host mechanics that
§11.8 incorporates by exact section and substitution. Nothing else in an older document is
normative for 0.5. The Swift keyring format that the shipped apps write is specified in §16.3
so that every binding can verify a predecessor.

MUST, MUST NOT, SHOULD and MAY are requirements on a conforming reader or writer.

## 0. Overview

An account is a keyring of controllers (passkeys, security keys, device keys, kits) whose
identifier is the digest of its first authority record. Members (apps, devices, agents, servers)
act under grants; short sessions act for members through links and calls; homes keep and vouch
for the history. A plain overview is in [colophon-0.5-guide.md](colophon-0.5-guide.md) §0.

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

**One verification order, for every object:**
1. Bounded generic parse: bounds, duplicate members, canonical bytes, the protocol marker, and
   every known field that a later step reads, each checked when parsed (`malformed`).
2. Bind the account and the claimed signer; verify every signature, possession proof, threshold
   and key binding (`badSignature`).
3. Check authorization (`refused:<reason>`, or `badSignature` for an authority rule).
4. Only then interpret unknown fields, kinds or values (`newerFormat`).
5. Check the rest of the typed schema (`malformed`).

A failure at an earlier step always wins. Unknown content that is not yet authenticated never
yields `newerFormat`. An unknown **protocol marker** is never authenticated content: it names an
object type this reader can't verify and is `malformed`. A signature by a key whose descriptor has
an unknown `form` can't be decided: it is `newerFormat`, reported only after every other check of
the object has passed (never before authentication), as the last result before `ok`. Such a
descriptor reached the reader only in an entry that was itself authenticated, or in a genesis
anyone could have made. For calls,
links, requests, heads and receipts, every known field is read by a later step, so step 5 is empty;
for authority entries, step 1 is §8.5's header and kind-specific fields are step 5.

## 2. Encoding and parsing

### 2.1 Canonical JSON

Every signed body is the UTF-8 encoding of one JSON object, so its first byte is `{` (0x7B).
Writers encode with object keys sorted recursively by their UTF-8 bytes, no insignificant
whitespace, slashes unescaped, non-ASCII characters as UTF-8, and the minimal escapes JSON
requires. Numbers follow the serde_json 1.0.145 writer with Ryū formatting: integer tokens
within the signed or unsigned 64-bit range in decimal without leading zeros; other numbers as
IEEE-754 binary64, correctly rounded, written as the shortest round-tripping decimal (when two
shortest decimals both round-trip, the one nearer the exact value; if both are equally near, the
one whose last digit is even, as Ryū and ECMAScript, not half-up) with
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
  `YYYY-MM-DDTHH:mm:ss.sssZ` with exactly three fraction digits, years 0001–9999. The calendar
  date and time MUST exist (no February 30, no hour 24, no second 60); anything else is `malformed`, never
  "no expiry". Comparison uses the components with omitted milliseconds as zero.
- **Digests** are lowercase hex SHA-256 of exact bytes, 64 characters unless "first 32".
- **Integers** in fields defined here are integer tokens from 0 to 2^53−1 unless stated.
- **Printable ASCII** is bytes 0x21–0x7E; space is not printable.
- **Equality** of authority entries, records, heads and receipts is equality of their body bytes.
  **Several envelopes over one body are one object**, for authority entries, transitions, vetoes,
  receipts, heads, requests and operation headers alike. The object is valid where any envelope
  held over it verifies; among those that verify, the first in byte order (of the envelope bytes)
  is the one kept; an envelope that does not verify is ignored and never makes the object fail.
  Nothing depends on which envelope arrived first, and a store MAY keep several.
- **Signature bytes are never identifiers.** ECDSA signatures are malleable (high-S is valid,
  §4.3), so no record, cache, replay store or index may be keyed by signature bytes or by a
  digest of an envelope that includes them; use body digests, `requestId`s and key IDs.

### 2.3 Strict parsing and closed field sets

- Any JSON object, at any depth, with a duplicate member name is `malformed`, including
  `clientData` and operation payloads.
- A string containing a lone surrogate escape (`\ud800` without its pair, or the reverse) is
  `malformed` everywhere, including in members a reader ignores and in `clientData`.
- Values nest at most 64 containers deep; deeper is `malformed`.
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
| Transition envelope | 622,592 |
| Veto envelope | 131,072 |
| Veto body | 4,096 |
| Receipt envelope | 1,024 |
| Receipt body | 512 |
| Membership request body | 16,384 |
| Link body | 8,192 |
| Call body, including embedded links | 65,536 |
| `args` of a call | 16,384 |
| Head body | 4,096 |
| Equivocation evidence | 2,097,152 |
| Operation header body (including `ciphertext`) | 16,777,216 |
| `clientData` | 8,192 |

Exceeding a bound is `malformed`, wherever the object is, including a `clientData` inside any
envelope. A verifier MUST NOT allocate in proportion to a claimed length before checking it.

**Predecessor chain.** A verifier follows the accounts along `predecessor` references from the
claimed account (§15.1), at most 16. A chain of more than 16 accounts is `malformed`. Objects in
the supplied set that no step of the chain reaches are ignored: they are never counted and never
a reason for `malformed`.

**The bounds compose.** The largest recording entry is a `vetoed` at `headQuorum` 8: base64 (4⌈n/3⌉)
of a transition envelope (622,592 → 830,124), a veto envelope (131,072 → 174,764) and 16 receipt
envelopes (1,024 → 1,368 each, 21,888), plus at most 2,048 bytes of header, field names and
punctuation: 1,028,824 ≤ 1,048,576. Every other entry embeds a subset. A veto body of 4,096 bytes
holds 64 signer IDs (64 × 35 + about 300). An honest WebAuthn signature item is about 1.5 KB, so 64
of them fit in a veto envelope; an envelope over its bound is `malformed`, whatever its signers.

**Portability floor.** Every service and verifier MUST be able to verify, on first contact, an
account whose history and pending objects together have at least:
- 65,536 authority entries;
- 4,096 transitions, vetoes and receipts held outside the history (copies embedded in entries
  count only as those entries);
- 256 MiB of envelopes;
- 262,144 signature verifications, counting every signature of authority entries, transitions,
  vetoes, receipts, heads, `handover`, `additions` and embedded requests.

Pages hold at most 64 entries (§14). The floor binds services and verifiers; a core MAY count
toward it for them. A service MAY set higher limits, MUST document its limits, and answers
`unavailable` beyond them, never partial validity. It MUST NOT impose a time limit that refuses an
account within the floor; clients MAY verify in the background. Verification resumes from
persisted state (§13.3). The rate limit (§13.1) keeps an honest account far below the floor.
Hosts MUST warn the owner when an account passes half of it.

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
| `origins` | `webauthn` only, optional. 1–32 distinct strings, strictly ascending by bytes. Each is a **web origin**, `https://` followed by a host in the `rp` grammar and nothing else, or a **platform origin**, 1–512 printable ASCII bytes (§2.2) not starting with `http:` or `https:`. |
| `authorityOrigins` | `webauthn` only, optional. 1–32 distinct origins, strictly ascending, each allowed for this descriptor by §4.3's general rule. |

The **key ID** is the first 32 lowercase hex characters of SHA-256 of `signing`.

### 3.2 What `rp` means

`rp` is the WebAuthn relying-party ID the credential belongs to. **Security invariant:** whoever
controls code on any origin a browser allows for an `rp` (the `rp`, every subdomain, and any
related origin it publishes) can obtain that `rp`'s passkeys' signatures over any challenge and
PRF output for any salt, and so read every `prf` slot of them. No field in an account changes
this; `authorityOrigins` separates who can obtain authority signatures, not vault access. Why, and
what follows for deployments, is in [colophon-0.5-guide.md](colophon-0.5-guide.md) §3.

- A host that registers a keyring passkey MUST use an `rp` whose every subdomain and related
  origin is operated as a ceremony origin of one release channel, and MUST NOT let a release of
  a different channel (for example staging, or a TestFlight or internal-track build) run code on
  any of them or appear in its association files. A non-production release MUST use a different
  `rp` for any passkey it creates.
- The bare `rp` origin SHOULD serve only `/.well-known/` association files.

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
persist it; the host persists it only inside slots. The core never returns seed bytes or a raw
ECDH output (§17.1 states what an opened seed can be sealed to).

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
- Recording entries (`activate`, `vetoed`, `successionVetoed`) carry only `body` (§8.7).
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
is `https://` followed by a host with no port, path, query, fragment or user information that
equals `rp` or is one or more labels of the `rp` grammar (§3.1: lowercase ASCII letters, digits
and `-`, 1–63 bytes, not starting or ending with `-`), each followed by `.`, then `rp`.

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
| `slots` | 1–256 at genesis; 0–256 after an activation drops slots (§8.3). A `keyring` entry MUST NOT leave more than 224; only `activate` may use the rest. |

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
| `primaryHome` | Member ID of the primary home. Absent: the earliest-appointed current home (homes appointed together in `appoint` order). | a current home |
| `rate` | `{"signer":{"entries","bytes"},"account":{"entries","bytes"}}`: immediate entries allowed per 24 hours of `issued` (§13.1) | signer entries 16–1,024, bytes 1–64 MiB; account entries 64–4,096, bytes 4–256 MiB |
| `recoveryDelay` | Seconds a pending transition waits for a veto (§8.7) | 0–2,592,000, and at least 3,600 while the account has a home |

An entry that leaves the account with one or more homes and `recoveryDelay` below 3,600, or with
fewer current homes than `headQuorum` while it has any home, or names as `primaryHome` a member
that is not a current home, is `malformed`. Which policy changes are immediate and which are
pending is in §8.4.

### 6.4 Warnings

Hosts MUST warn, in words, before writing anything after which any of these holds (suggested
wording is in [colophon-0.5-guide.md](colophon-0.5-guide.md) §2):

- losing any one key (or holder) leaves no control quorum, no recovery quorum the person chose, or
  no openable slot;
- fewer recovery controllers exist than the person chose, or none has a slot;
- the account has a `recover` controller and no home (no theft safety, §8.7);
- the account has one home;
- every control key is on one device (for example a phone's device key and its synced passkey);
- all recovery keys are kept together;
- the `recover` controllers form exactly one unit (one key, or under `countBy: holders` every
  recovery key of one holder): an account SHOULD have zero or at least two recovery units, and a
  host MUST warn before creating or leaving one with exactly one, saying that a thief holding any
  one control unit can then block recovery for ever (a stall) and that the full, immediate
  recovery needs two units;
- a company has two holders and `threshold` 2 or `threshold` 1;
- a remaining controller has no slot after a rotation, or the vault is retiring (§8.3);
- a home has signed no head for longer than `recoveryDelay`: until it is revoked, no addition can
  become final, and revoking it is an ordinary transition (§8.7 "Revoked witnesses").

## 7. Vault and slots

### 7.1 Vault

The vault seed is 32 random bytes from the host. Its identity is
`s' = HKDF-SHA256(IKM = seed, salt = "colophon/vault/4", info = "identity", 32 bytes)`, then the
software-identity procedure of §7.5 on `s'`. The `/4` in these and the slot labels is a
domain-separation label, unchanged in 0.5.

**Each newly introduced epoch MUST be sealed to exactly the current vault and the active,
unexpired members with any access to its namespace (§10.2), at the introducing entry.**
Historical seals stay valid; epochs sealed to an earlier vault are reached through
`previousVault` (§8.3). Later `shares` add only recipients this document authorizes. A member that
is provisional (§8.7) or expired when an epoch is made is not sealed to it; it gets its shares by
a `renew` (§9.4) once its activation is final or it is current again.

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
challenge (never a body digest), never from registration. The assertion's origin is judged by
the general origin rule of §4.3 for that credential's `rp` and `origins` (the authority-origin
restriction does not apply: this is not an authority signature), and UV is required exactly
when the controller has `verification: true` (§4.3 step 3). The core verifies that assertion
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
§7.4's label has both nonces; no code is compared. **QR payload bytes:** the canonical JSON of
§2.1, as UTF-8, of the closed object
`{"account":"<64 hex>","e":"<base64>","nB":"<base64>","protocol":"colophon/pair-qr/5"}`: `account`
is `accountID`, `e` the 65-byte point and `nB` the 32-byte nonce, standard padded base64
(§2.2), keys sorted as §2.1 says (`account`, `e`, `nB`, `protocol`). A reader parses strictly
(§2.3), refuses any other member, protocol, length or non-canonical byte, and an `E` that is
not a valid point.

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
kit is a software identity from 32 secret bytes `K` the host prints or stores, with **one**
derivation, the one 0.3 and 0.4 use: `s' = HKDF-SHA256(IKM = K, salt = "colophon/recovery/3",
info = "identity", 32 bytes)`, then the expansion above on `s'`. A kit made under 0.4 therefore
keeps its keys after an in-place upgrade (§16.1). It is a `raw` controller with `agreement`,
usually `recover` only.

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
| `vault` | `vault`, `slots`, `previousVault` | Rotates a retiring vault (§8.3). |
| `suspend` | `key`, `transition`, `receipts` | Suspends a key while a transition removing it is pending (§8.7). |
| `activate` | `transition`, `receipts` | Applies a due transition (§8.7). Unsigned. |
| `vetoed` | `transition`, `transitionReceipts`, `veto`, `receipts` | Records a vetoed transition (§8.7). Unsigned. |
| `final` | `activation` (`{seq, digest}`), `heads` | Records that an activation is final (§8.7). Unsigned. |
| `successionVetoed` | `veto`, `receipts`, `genesisReceipts` | Records a veto of this account's own succession from a Swift predecessor (§15.1). Unsigned. |

`transition` and `veto` are embedded envelopes (§2.2). `receipts`, `transitionReceipts`,
`genesisReceipts` and `heads` are arrays of embedded envelopes, chosen and sorted as §8.7 says.
`shares` and `epochs` are arrays of epoch objects (§11.1) sorted by namespace, then epoch; in
`shares` each `seals` holds exactly the recipients the entry adds. **Recording entries** are
`activate`, `vetoed`, `final` and `successionVetoed`.

`namespaces` is 0–64 distinct sorted names of lowercase ASCII letters, digits, `.` and `_`, at
most 128 bytes. A `/5` account is at layout 2 from genesis (§11.8). Raising the layout and
writing `migration` are transitions (§8.4).

### 8.3 Keyring changes and the vault

Immediate `keyring` entries only add or tighten (§8.4); transitions do the rest (§8.7). When the
vault is unchanged, every existing slot stays (multiset by canonical JSON without `label`) except
those an activation drops, and labels and order may change.

**Removing a slotted key needs no vault change.** A transition may remove or demote a controller
that a slot or part of the current vault names, or change its `agreement`, by its ordinary rule:
one recovery key can start it. At its activation every slot naming that controller is dropped
(an account may then have no slot), and the vault is **retiring**: the removed key may still know
its seed. While the vault is retiring:
- **Keys the removed key planted go too.** At the activation of a transition that removes a
  controller K, every controller K added by immediate entries after the transition's anchor is also
  removed, unless the transition's `keep` names it.
- The host of a controller holding the seed that was current at the anchor of the removal that
  made the vault retire, is still current, and holds `control` or `recover`, MUST at once append a
  **`vault` entry**: `vault` (a fresh identity, §7.1), `slots` (one naming
  its signer, and every other remaining controller's slot that this host can build: every
  `sealed` slot, and `prf` or `combined` slots whose credentials are present) and
  `previousVault` (below). One such signer suffices. It ends the retirement.
- A remaining controller without a slot in the new vault gets the new seed by §7.4 from a device
  that holds it, the next time it is present, and adds its own slot by a self-slot `keyring` entry
  (§8.4). Hosts MUST warn (§6.4) while a remaining controller has no slot. The old seed is
  retired once every remaining controller that had an old slot has a new one; until then it opens
  only what it opened before.
- Hosts MUST NOT introduce epochs, and a `revoke` carries empty `epochs` (§9.5); the `rekey` after
  the rotation covers them. A verifier refuses a `rekey`, or a `revoke` with non-empty `epochs`,
  while the vault is retiring.
- **What the removed key can still read:** everything sealed to the retiring vault, which is every
  epoch introduced before the `vault` entry and every record under them, including records written
  while the vault was retiring. Nothing introduced after the `vault` entry is sealed to it.

**A vault change inside a transition** is the component `{"vault":{…},"slots":[…],"previousVault":{…}}`,
for a voluntary rotation, or a removal proposed by a seed holder that rotates at once. At
activation slots added after the anchor, and slots of controllers it removes, are dropped; it then
leaves the vault not retiring.

**`previousVault`** is the current vault seed sealed to the new vault: HPKE (§11.1 suite) to the
new vault's agreement key with `info` and AAD
`"colophon/vault-previous/5\n" ‖ newVaultID ‖ "\n" ‖ oldVaultID`. Whoever opens the new vault
opens this to reach the old vault and every epoch sealed to it, and so on back through the
history. It is required in a `vault` entry and optional in a transition (absent when the proposers
can't open the current vault; older epochs are then not reachable through the new vault).

After any vault rotation, the host of any controller holding the new seed appends a `rekey`
introducing a new epoch in every namespace (§8.4: a `recover` signer suffices), and writers MUST
NOT seal new records under an epoch introduced before the rotation until it exists. Hosts MUST
build every new slot to open the new vault; verifiers can't check that.

### 8.4 Who may sign what

Signers are evaluated against the state immediately before the entry; for a transition, before
its `activate` (§8.7). `sign` controllers never count, and neither does anything added by an
activation that isn't final (§8.7).

**Immediate entries.** Each is subject to the rate limit (§13.1). What one key can do with each,
and its bound, is in [colophon-0.5-guide.md](colophon-0.5-guide.md) §1.

| Kind | Rule |
| --- | --- |
| `genesis` | Control rule over its keyring; possession; predecessor rule (§15.1). The primary signature is the primary signer's possession proof. |
| `grant`, `renew`, `revoke` (not homes, not `import`) | Single rule; control rule when `memberRule` is `control` |
| `rekey` | Single rule, or one `control` or `recover` signer; control rule when `memberRule` is `control` |
| `endSessions` | Single rule, or the member rule; control rule when `memberRule` is `control` |
| `keyring` | `addThreshold` units holding `control`, with UV, plus possession. It may only: add at most four controllers, each with roles `["approve"]` or `["sign"]` (with slots for them in the same entry); add slots for existing non-`sign` controllers; change labels; and tighten the **signing controller's own** authentication or policy (§6.3 lowering only). **Self-slot:** an entry whose only change adds slots to the current vault naming only its signer may be signed by that one non-`sign` controller. |
| `vault` | One controller holding `control` or `recover`, current at the anchor of the removal that made the vault retire and still current, only while the vault is retiring (§8.3). An `approve`-only key never rotates a seed. |
| `suspend` | One signer of the pending transition it carries (§8.7) |
| Recording entries | §8.7, §15.1 |
| `upgrade` (`/4`) | 0.4 control rule (§16.1) |

**Pending transitions.** Everything else, including unknown change members and anything in
doubt. Each needs the control rule unless stated:

| Change | Also |
| --- | --- |
| Remove or demote a controller; add `control` or `recover`; `keep` | **Recovery.** The recovery rule may also remove any controllers and add replacement controllers with `approve` and `control` (never `recover`); signed by every current `recover` controller, and by at least two units, it is a full set (immediate, §8.7); otherwise it is pending, open to veto and escalation, so an account with one recovery unit recovers only by a pending transition, which completes after the delay unless it is vetoed (one unit against one is a stall, §8.7). `keep` needs the recovery rule. The result must still have a `control` controller (§6.2). |
| `threshold`, `addThreshold`, `recoverThreshold`, `countBy` | Count the larger of old and new `threshold` |
| Another controller's descriptor, `verification`, `origins`, `authorityOrigins` or `holder`, in either direction | The labelled key signs a holder change |
| Delete or change a slot; change the vault | The recovery rule may also propose a vault change with its own removals |
| Revoke a home | The recovery rule may also propose it; who must witness it is in §8.7 "Revoking a home" |
| Appoint or renew a home; `primaryHome`, `headQuorum` | The recovery rule may also propose these when `recoverThreshold ≥ threshold`, or in a full set |
| A grant with `import`; `recoveryDelay`; raising `rate` | — |
| Raise `headMaxAge`, `callWindow`, `linkMaxAge`; `memberRule` to `single`; `history` to `public` | — |
| `layout`; `migration` (only with a `predecessor`); `successor`; `resolve` (control rule in the recording state and control rule of the keyring before the fork, §8.6 "Resolving a fork") | — |

**Recovery-set consent.** When the state before activation has `recoverThreshold ≥ 1`, a
transition also needs `recoverThreshold` `recover` units if any component:
- removes, demotes or adds `recover`;
- changes a `recover` controller's fields other than `label`, or its slot;
- changes the vault while a `recover` controller has a slot;
- changes `recoverThreshold`, `recoveryDelay`, `countBy`, `headQuorum`, `primaryHome`, `rate` or homes;
- raises `threshold`;
- is `layout`, `migration`, `successor` or `resolve`.

A transition meeting the recovery rule has consent.

**Rules.**
- **Control rule:** `control` units at least the larger of the old and new `threshold`; other
  signers may hold `control` or `recover`.
- **Recovery rule:** every signer holds `recover`; at least `recoverThreshold` units.
- **Single rule:** exactly one signer holding `approve`.
- **Member rule:** `endSessions` signed `raw` by the member it names.
- **Possession:** every controller added, and every controller whose `holder` is set, signs the
  body in `additions`, from an authority origin (a `sign` controller's from any origin its
  descriptor allows). Exempt: `upgrade`, and, at a successor genesis, keys whose descriptors equal
  predecessor keys current at `head`, but only when the succession is authorized (§15.1): for a
  Swift predecessor, when the genesis's `handover` meets the rule that may write F at `head`; for
  a `/5` predecessor, when the succession is verified, which needs F final. Without that, every
  listed controller needs its possession proof, and a genesis lacking one is `badSignature`. For a
  `/5` predecessor whose F is absent or provisional the succession is not decided yet, so a genesis
  that lacks a proof for a carried key is **held** (§8.5): it becomes `ok` when F is final and
  `badSignature` when the predecessor has another entry at F's seq, such as the `vetoed` that
  displaced F. A verdict may go from held to ok or from held to refused, never from ok to refused.
  A genesis that carries a proof for every controller is valid on its own, with the succession
  simply unverified. An unverified or vetoed succession still confers nothing (§15.1).
- **UV.** Required on every WebAuthn signature under the control or recovery rule, on immediate
  `keyring` and `vault` entries, and on transitions, vetoes and `handover`. Single-rule,
  `rekey`, `suspend` and possession signatures need UV only when the controller has
  `verification`.

**Removal follow-up.** A host building the removal of a controller MUST list in the same
transition, by default, every `approve` or `sign` controller the removed key added by immediate
entries, and SHOULD use `keep` when a recovery key signs.

### 8.5 Verification order and results

For seq > 1 the verifier MUST, in this order (the pipeline of §1):

1. Bounded generic parse (duplicates refused). Header: `protocol` (as §8.1 allows here), `seq`,
   `previous`, `issued` (format and monotonic). `by` names a controller of the prior keyring (or,
   for `endSessions`, a current member; for `activate`, `vetoed` and `final`, the `by` of the
   embedded transition, veto or activation; for `successionVetoed`, an eligible predecessor key,
   §15.1). An `issued` more than 60 s ahead of the verifier's clock: *held*.
2. Verify every attached signature (§4) against the prior keyring, member table or added
   controllers.
3. Decide the rule (§8.4; unknown kinds use the control rule), and for `suspend` and recording
   entries the checks of §8.7's state table.
4. Only now look for unknown content anywhere in the body (`newerFormat`).
5. Apply the typed schema, bounds and the rules of §6, §7.2 (every slot's shape, kind fields and sizes), §8.2, §8.3, §9, §13, §15 and §16, and the
   rate limit (§13.1).

Genesis follows the same order with its own keyring. No verifier may be stricter or more
lenient than this section for authority entries. **Every failure has exactly one result:**

| Failure | Result |
| --- | --- |
| Bounds, parse, header, canonical bytes, an oversized `clientData` | `malformed` |
| `by` not as step 1 requires; a signature that fails or is foreign | `badSignature` |
| A rule, consent, threshold, possession or escalation not met — by the entry, or by a transition it embeds; a signer (of the entry or of an embedded transition) not current with the role it signed with, suspended, or added by an activation with no `final` | `badSignature` |
| An embedded receipt, head or veto signature that fails | `badSignature` |
| A transition or veto whose `signers` doesn't match its envelope (checked before its rule) | `malformed` |
| Every other failure of an embedded object: receipts (missing, wrong homes, wrong count or choice, outside their window), anchor, veto unit count, disjointness, vetoer role or currency, deadline, determined fields, once only, the 7-day bound, heads in `final`, one suspension per unit, a void delta | `malformed` |
| Unknown content after steps 1–3 pass | `newerFormat` |
| A transition that revokes a home and adds anything; a `final` with no heads | `malformed` |
| Schema, §6, §7.2 (slot shape) and §8.3 violations, the rate limit | `malformed` |
| `issued` ahead; an `activate` whose objects are all valid and whose due time is after the clock | *held* |

### 8.6 Conflicting entries

Entries are equal when their bodies are equal. Two **conflicting** entries are valid entries with
the same `seq` and `previous` and different bodies. A verifier classifies a conflict between X and
Y using only the objects it holds — entries, transitions, vetoes, receipts and heads — so every
verifier holding the same objects reaches the same verdict, in any order. What it held before
never selects a branch (§13.3). Several envelopes over one body are one candidate (§2.2): it is
valid when any of them is, and an envelope that does not verify is ignored.

With more than two valid candidates, apply the comparisons below to every pair. A candidate
stands only if every comparison involving it selects it. If none does (including a cycle), the
conflict is an unresolved fork under rule 3; no candidate is dropped. Pairwise comparisons need
not be transitive, and MUST NOT be folded into a running winner.

Every recording entry has a **due time**: an `activate`'s or `vetoed`'s is its transition's; a
`final`'s is its activation's transition's; a `successionVetoed`'s is the succession's.

"A `final` covers" an `activate` as §8.7 defines under "Final": the activation is final, in any of
the ways given there, on its own branch. A `vetoed` that displaces an activation removes every later
entry on that branch (§8.7 Rollback), including any entry that would have made it final, so
either the activation is final on its branch and no `vetoed` displaces it, or it is not and the
`vetoed` takes the branch with it.

1. **Activation order.**
   - If X is a recording entry and Y is not, **Y stands only if** the verifier holds a head of the
     primary home (in the state before seq n) covering Y, Y's `issued` is not later than X's due
     time, and no `final` covers X's activation; otherwise X stands. Homes refuse immediate entries
     dated more than 300 s before their clock (§13.1), so an honest primary covers no backdated Y.
   - Between an `activate` and a `vetoed` of one transition, the `vetoed` stands if its veto is
     valid, unless a `final` covers the `activate` (§8.7).
   - A recording entry whose activation is **final on its branch** (§8.7 "Final": an `activate`
     that is final, or a `final` entry) stands against a recording entry of **another object**
     whose activation is not; nothing displaces a final activation. If both are final, or the
     objects are the same, the order below applies.
   - Between other recording entries the order is total, comparing in turn: the earlier due time;
     the lower **object digest** (the transition body's for `activate`, `vetoed` and `final`, the
     genesis body's for `successionVetoed`); the kind rank (`activate` 0, `vetoed` 1, `final` 2,
     `successionVetoed` 3); the lower body digest. Every kind has a value at every step. Two recording entries of one kind for one transition differ only in receipts or heads:
     the one that loses is **dropped**, never rebuilt.
   A recording entry that loses to an entry of another transition is rebuilt after the head by any
   home. A signed entry that loses is not re-appended by anyone else: its signer's host is told
   (409, §14) and MUST offer to sign it again at the new head.
2. **Equivocation.** Otherwise, if X is covered by heads of `headQuorum` current homes and no
   current home's head covers Y, X and Y are equivocation evidence (§13.3) against the signer
   units present on **both** entries; a signer of only one of them may have raced honestly and
   is not convicted.
3. **Fork.** Otherwise — no head evidence for either, heads for both, or an account without homes
   — both entries are equivocation evidence (§13.3) against the signer units present on both, and
   every verifier answers
   `refused:fork` for everything that depends on either branch until a `resolve` transition
   activates on one branch. A transition anchored on a losing branch is void.

Records citing a seq at or after an unresolved fork are held.

**Resolving a fork.** A `resolve` transition (§8.7) carries `kept: {seq, digest}`, an entry at the
forked seq. It is built on the branch that holds the kept entry: its anchor is an entry of that
branch, and it is **valid when the kept entry is on the branch its `activate` is recorded on**.
Its effect: every other candidate at that seq, held now or shown later, is discarded for a
verifier following this branch. A verifier that holds no other candidate treats the `resolve` as
valid and changing nothing, so no honest verifier is ever stopped by it, whether or not homes
serve the losing entry.
- **Who signs.** Both rules hold: the ordinary control rule (§8.4) in the state the entry is
  recorded in (the kept branch's own keyring and threshold), consent and currency included; and
  the control rule of the keyring before the fork (the state after seq `kept.seq − 1`): the
  signers that held `control` there must reach that keyring's `threshold`, so a controller that a
  branch added after the fork adds nothing. It is recorded as any transition is, an `activate`
  entry with receipts, due time and veto as §8.7 says.
- **Choosing the branch.** At a conflict §8.6 rules 1 and 2 leave open, a candidate **keeps
  itself** when its branch holds a valid `resolve` activation whose `kept` is that candidate's
  entry at the seq. It stands if it is the only candidate that keeps itself and no other
  candidate's branch holds an activation after the fork that homes witnessed (below). One
  `resolve` settles a fork of any number of candidates. A `vetoed` that displaces the activation
  (§8.7) leaves the fork open again. The verifier looks for the activation along each candidate's
  own branch up to the first later unresolved conflict on it; a later fork on a branch that
  already holds a `resolve` is resolved the same way, by its own `resolve`.
- **Two `resolve`s.** Nothing orders resolves. If two candidates each keep themselves, neither
  resolves the fork and rule 3 stands; no candidate is dropped.
- **Witnessed branches are never discarded.** A `resolve`, and rule 3 generally, never discards a
  branch on which an activation after the fork point is final **as witnessed by homes**: made
  final by a `final` entry with the witnesses' heads (a full set counts once its own `final`
  carries heads). Finality by excusal, an empty witness set or a later full set's anchor is not
  witnessed. A late fork by a former controller therefore cannot win in an account with homes;
  the owner's own `resolve` keeping the witnessed branch settles it.
- **The losing branch.** Its entry at the forked seq and everything after it on that branch are
  not part of the account's history; they stay equivocation evidence under rule 3, and nobody
  appends them again. Transitions anchored on them are void.
- **The limit.** An account with no home has no witness of time or order: everything on it is
  final at once on every branch alike, so a former controller can show a new verifier a different
  history from before its removal (a late entry and a `resolve` keeping it), and nothing in the
  objects tells the two apart (§13.1, §18).

### 8.7 Pending transitions

```json
{"protocol":"colophon/transition/5","account":"<64 hex>","anchor":{"seq":41,"digest":"<64 hex>"},
 "issued":"…","by":"<keyID>","signers":["<keyID>","…"],"change":{"keyring":{"remove":["<id>"]}}}
```

**The objects.**
- **Transition.** `signers` is the sorted list of the primary signer (`by`) and the cosigners,
  never `additions`; an envelope whose signatures don't match it is `malformed`. Signatures are
  authority signatures (§4.3). `anchor` names an entry the proposer verified; `issued` is not
  earlier than the anchor's. `change` has one or more components: `keyring` (`add`, `remove`,
  `keep`, `update` with whole replacement controllers, `threshold`, `recoverThreshold`,
  `addThreshold`, `countBy`), `policy` (fields to set; `primaryHome: null` unsets it), `vault`
  (§8.3), `homes` (`appoint: [{request, terms}]`, `revoke`), `grant` (`{request, terms}` with
  `import`), `layout`, `migration` (§15.4), `successor` (`{account}`), `resolve`
  (`{kept: {seq, digest}}`, `seq` at least 2; §8.6 "Resolving a fork").
- **Composite rule.** One signer set meets, for every component, a rule that component allows,
  using the same rule (control or recovery) for all; consent if any component needs it;
  escalation and the full set judged once over the whole. It activates atomically or not at all.
- **Delta at activation.** `remove` of an absent ID, a `keep` naming an absent ID, or `add` of a
  key present with the same roles, does nothing. `keep` lists every controller without `recover`
  that remains; every other one, including any added after the anchor, is removed. `add` of a
  present key with other roles, or `update` of an absent ID, voids the transition, as does a
  transition that changes nothing or whose result breaks §6.
- **Veto.** `{"protocol":"colophon/veto/5","account","transition":"<body digest>","issued","by","signers":[…]}`,
  authority signatures. Signed by at least as many units as the transition, none a signer unit of
  it, each a `control` or `recover` controller current in the state before the entry recording
  it; a key the transition would remove may sign.
- **Receipt** (§13.5): by a current home, `received` within 300 s after the object's `issued`.
  **Choosing receipts (a rule for a recorder):** an entry carries exactly `headQuorum` receipts for
  an object, from the homes with the lowest member IDs whose valid receipts the recorder holds,
  for each home its receipt with the lowest body digest, sorted by home ID, so honest recorders
  holding the same receipts build the same entry. For a veto the receipts that may be chosen are
  those valid under §13.5 and **received at or before the transition's veto deadline**; a later
  receipt is skipped, never chosen, and never blocks the entry. **A verifier judges only the
  receipts the entry carries, for validity:** `headQuorum` receipts (at most the current homes)
  from distinct current homes, sorted by home ID, each valid under §13.5, in window and, for a
  veto, at or before the deadline. It never refuses an entry because a different valid receipt
  exists or is held: a verdict that depended on which objects a verifier holds would let one
  home split verifiers. Two `vetoed` (or two `activate`) entries for one object that differ only
  in receipts are ordered by §8.6 rule 1 (the lower body digest stands, the other is dropped). A
  home that signed two receipts for one object is a matter for equivocation evidence, never a
  reason to refuse an entry.

**Times.** For a transition T judged in state S:
- the delay is the larger of `recoveryDelay` at T's anchor and in S;
- **due** = T's `issued` + 300 s + delay; **veto deadline** = T's `issued` + delay;
- a **full set** (below) is due at its latest chosen receipt's `received`, or at its `issued` if S
  has no home; it has no veto deadline.

**Validity of T at an entry E** (`suspend`, `activate`, `vetoed`), against the state S immediately
before E:
1. its signers meet the rule, consent and escalation, and each is current with the role it signed
   with (`badSignature`);
2. it has `headQuorum` valid receipts from distinct homes current in S, unless S has no home
   (`malformed`);
3. its anchor is on E's branch (`malformed`).

A transition whose only receipting homes are revoked before activation is dead.

A home admits a transition (receipts it) by judging it at the home's **current head**, not at a
later state (§13.1); validity at an entry is judged at that entry, as above.

**Escalation.** v(u) is the number of distinct transitions signed by unit u with a `vetoed` on the
branch since the last `activate` of a transition u signed that met the escalation rule then. T
with signer units U needs |U| ≥ 1 + max v(u) over U, checked at receipt and again at activation.
A unit removed and re-added keeps its count. It terminates: each veto raises v for every signer
and |U| ≤ 64. Equal sides **stall**: both keep their immediate powers, until one side obtains
another unit.

**Full set.** T is a full set, can't be vetoed and is due as above when it has at least two signer
units and either (a) meets the recovery rule and every current `recover` controller signed it, or
(b) meets the control rule, every current `control` controller signed it, and, if it needs
consent, every current `recover` controller too. "Current" includes every key T removes. Whoever
holds every recovery key is treated as the owner.

**Removal-only transitions.** A transition is **removal-only** when every component only
removes or demotes controllers (including by `keep`), revokes homes, raises a threshold or tightens
policy: it adds no controller, role, home, member or slot, lowers no threshold, loosens no policy
and has no `vault`, `grant`, `layout`, `migration`, `successor` or `resolve` component. A
transition that revokes a home and also adds anything is `malformed`.

**Revoking a home.** A home's revocation is the one removal that does **not** apply at
activation: a revoked home stays current — for receipts, heads, witnessing and quorum — until its
revocation is final. A transition that revokes homes under the control rule keeps them as
witnesses of its activation (below), so each must sign a head covering it; a home that won't
witness its own removal therefore stays. Removing such a home needs the **stronger authority** — a
full set, or the recovery rule where recovery controllers exist — whose activation's witnesses
leave out the homes it revokes, so finality needs only the remaining homes. An account with no
recovery controllers and a dead or unwilling home needs every control key (full set (b)) to drop
it.

**Liveness of recovery.** While `headQuorum` honest homes are current and reachable and the owner
holds every recovery controller, no one without the recovery rule can make those homes'
revocation final, so they stay current and receipt the owner's transitions. Then: every recovery
controller together, when they form at least two units, is a full set and can't be vetoed, so it
always completes, whatever the adversary holds. A vetoable recovery is sure to complete when the
owner's units outnumber the adversary's under escalation (it also completes if nobody vetoes).
With **exactly one** recovery unit — one key, or two keys of one holder under `countBy: holders` —
and an adversary holding a control unit, it is the equal-units stall: the adversary vetoes once,
escalation then needs two units the owner doesn't have, and neither side completes until one
obtains another unit.

**Finality is a recorded fact.** A verifier judges finality only from the objects it holds, never
from heads it has seen or the order it saw things in.
- An activation's **witnesses** are the homes current in the state before it (which include homes
  whose revocation isn't final yet; a home is excused only once its revocation is final), less the
  homes it revokes itself under the stronger authority. For a
  full set they are those of them that remain after it.
- **Final.** An activation is **final** when its remaining witness set is empty, or a `final` entry for it is on the
  branch, or a later `final` on the branch carries a head from every one of its witnesses covering
  it, or a later full set's anchor is it or follows it.
  After each entry, excuse homes whose removal-only revocation is final and make every activation
  with no remaining witnesses final without a `final` entry, in Order; repeat until no more
  become final. **A `final` covers an activation** (§8.6 rule 1) when it is final in any of these
  ways, in the state after it or after any valid entry that follows it on its branch: its witness
  set is empty or fully excused, a `final` entry names it, a later `final` carries a head from every
  one of its witnesses, or a later full set's anchor is it or follows it. This is the one meaning
  of "final" in §8.6, §8.7 and §15.
- **Choosing heads (a rule for a recorder).** A `final` carries, for each witness, one head: among
  the heads valid for it (signed by that home's key in the state before the activation, covering
  the activation on this branch, not necessarily fresh) and usable (not dated more than 60 s
  ahead of the recorder's clock, §13.3), the one with the lowest body digest, and its `issued` is
  the latest head's, so honest recorders converge. **A verifier judges only the heads the entry
  carries:** exactly one valid covering head per non-excused witness, signed under that home's key
  in the state before the activation, not dated after the entry's own `issued` (the measure is
  the entry's `issued`, not the verifier's clock, so a recorded `final` never changes verdict as
  time passes). It never refuses a `final` because a different valid head exists or is held; two
  `final` entries of one activation are ordered by §8.6 rule 1. A home with two heads at one seq
  is a matter for equivocation evidence (§13.3), never a reason to refuse an entry.
- **Order.** An activation that is not removal-only gets a `final`, or becomes final by excusal,
  only when every earlier activation that is not removal-only is final. Removal-only activations
  are outside this order: they never wait for an earlier provisional activation, and none waits
  for them. A revocation of a home that is not removal-only (it also loosens a policy field, say)
  revokes the home once final but does not excuse it, so activations that list that home as a
  witness wait for its head.
- **Until final, whatever an activation adds counts for nothing.** An added controller, home or
  member signs no entry, transition, veto, `suspend` or call (`refused:revoked`), counts toward no
  rule, unit, quorum, full set or escalation, and its receipts and heads don't count; records by an
  added member are held (`authorityBehind`). Removals and restrictions apply at once (fail-safe),
  final or not — except a home's revocation, which applies when final.
- **A final activation is never displaced.** A `vetoed` for its transition changes no state; it is
  equivocation evidence against every witness that receipted the veto (§13.3).
- **A provisional activation, removal-only or not, is displaced by a valid `vetoed` of its own
  transition** (§8.6 rule 1). A verifier holding the `activate` and not the `vetoed` applies the
  activation as provisional; when it receives the `vetoed`, the same rule displaces the activation,
  whatever order the objects came in. Once a `final` covers the activation, whether it is a
  `final` entry or finality by excusal, the `vetoed` changes nothing.
- **Rollback** of a provisional activation removes it and every later entry on its branch, and
  nothing else; nothing it added has signed. Transitions anchored on a removed entry are void;
  recording entries are rebuilt by the homes; displaced signed entries go back to their signers'
  hosts; escalation counts and suspensions are recomputed. Services MUST NOT take irreversible
  effects on entries after a provisional activation.

**Suspension** is an explicit `suspend` by a signer of a pending removal. While it lasts the key
signs no immediate entry and no call except `colophon.history.read`; it may sign vetoes and
transitions.

**Calls during transitions.** A key a pending transition would add is not a controller until its
activation is final. A key it would remove works until activation, unless suspended.

**No home.** There is no delay and no veto; conflicts are forks. **An account without a home has
no theft safety.**

#### The state machine

This table is normative; the prose above defines its terms. State is §17.2's. The **kind rows**
(all but the last two) partition the entries: each entry matches exactly one (`suspend`, `vault`
and full-set activations only their own). **Conflict** and **Clock** are meta-events, applied
after an entry has been classified by its kind row. "S" is the state immediately before the entry; every check fails
with the result shown, and an entry that fails changes nothing. Every recording entry has
`issued` determined as shown; another value is `malformed`.

| Event | Checks, in order | Effects |
| --- | --- | --- |
| **`genesis`** | §8.5 steps 1–5 against its own keyring; §15.1 for a predecessor | The initial state. |
| **Immediate entry E** (every kind except `genesis`, `suspend`, `vault` and recording entries) | §8.5 steps 1–2; signer current, not suspended, not added by a provisional activation (`badSignature`); §8.4 rule (`badSignature`); rate (§13.1, `malformed`); kind rules (`malformed`) | Apply. A suspension whose transition E makes invalid, or whose due time + 7 days is before E's `issued`, ends. |
| **`vault`** | As an immediate entry; the vault is retiring and the signer was current at the anchor of the removal that made it retire, is still current, and holds `control` or `recover` (`badSignature`); a slot names the signer, `previousVault` present (`malformed`) | New vault; not retiring. |
| **`suspend` (key K, T, receipts)** | §8.5 steps 1–2; signer is a signer of T (`badSignature`); T valid at E; T not recorded on the branch; T removes or demotes K; T's delta not void; the signer's unit has no outstanding suspension (`malformed`) | K suspended until the earliest of: T's `activate` or `vetoed`; the first entry after which T is no longer valid at a hypothetical `activate`; the first entry, or the verifier's clock, past T's due time + 7 days. |
| **`activate` (T, receipts)**, T not a full set | `by` = T's `by`; T not recorded on the branch; T valid at E; receipts chosen as above; `issued` = max(due, previous `issued`) and not more than 7 days after due (`malformed`); delta not void (`malformed`) | Apply the delta (with `keep`, §8.3's slot drops, retiring, and the drop of keys the removed key added); T recorded; v(u) reset for T's units if T met escalation; the activation is provisional with its witness set; it becomes final when every witness is excused, in Order (the fixed point). |
| **Full-set `activate`** | As `activate`, with the full set's due time; no veto | As `activate`; every activation before T's anchor becomes final. |
| **`vetoed` (T, transitionReceipts, V, receipts)** | `by` = V's `by`; T not recorded on the branch; T valid at E with `transitionReceipts`; T not a full set; V's units ≥ T's, disjoint from them, each a current `control` or `recover` controller; V's receipts: `headQuorum` from distinct current homes, sorted, each valid, within 300 s of V's `issued` and at or before T's veto deadline; `issued` = max(latest chosen veto receipt, previous `issued`), not more than 7 days after it (`malformed`) | T recorded; v(u) += 1 for each of T's units; suspensions citing T end. |
| **`final` (activation A, heads)** | A is an `activate` on the branch, not yet final; if A is not removal-only, every earlier activation that is not removal-only is final; `heads` is non-empty and has exactly one head per witness of A, each signed by that home's key in the state before A, covering A on this branch (not necessarily fresh); `by` = A's `by`; `issued` = max(latest head's `issued`, previous `issued`) (`malformed`) | A is final, and so is every earlier activation whose witnesses all have a head here covering it; what they added counts. A removal-only A that revoked homes excuses them from every other activation's witnesses. |
| **`successionVetoed`** | §15.1 step 4 (`malformed`; a veto signature by an ineligible key `badSignature`) | The succession is never verified. |
| **Conflict at one seq** | §8.6 | The standing entry is on the branch; rollback as above. |
| **Clock** | — | A held entry of any kind is decided when its `issued` is no more than 60 s ahead; a held `activate`, when its due time passes; a suspension ends at its due time + 7 days. |

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
has a requested entry for the same namespace whose access is equal to or higher than the granted
access and, if requested `kinds` are present, granted `kinds` that are a subset of them; each granted `services` entry matches a
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
and the member's current expiry; to shorten access, revoke. The member MUST be current and have an
expiry; renewing a member with none is `malformed`.
`shares` seals every epoch in its `records` scope it lacks, including epochs introduced while it
was expired. Nothing else changes.

### 9.5 Revoke

`revoke` ends `member`. `epochs` introduces a new epoch in every namespace the member could read
(every namespace of its `records` entries; empty if none): for each, the namespace's current epoch
plus one, at most one per namespace, as a `rekey`'s (§8.4). A verifier refuses a `revoke` that
omits a namespace the member could read. **While the vault is retiring (§8.3), `epochs` is empty**
(a new epoch would be readable by the removed key), a verifier refuses a `revoke` with non-empty
`epochs`, and a `rekey` for those namespaces is owed once the new vault is in place. A record by
the member is **kept** exactly when:

- its header-body digest is in `kept` (sorted, distinct; any header digest, `/3` or `/5`, live
  or not); or
- it is reached by the **walk**: start at each item of `heads`, an array of
  `{"namespace","digest"}` objects sorted by namespace then digest, at most 16 per namespace, each
  naming a header of this member in that namespace, and follow
  `previous` from header to header, through any held header whose body digest matches, whether or not
  that header is itself admitted and whatever its author or namespace.
  An item that names a held header of another author or another namespace starts no walk and is
  not an error; an item whose digest no held header has makes the walk incomplete (below).

A kept record still passes every other admission check, and a kept record citing the revocation
seq or later is refused `revoked`. A reader that cannot complete a walk, because a `heads` item or an intermediate
header is not held, is **incomplete** for that revocation: it holds as *held* (`unavailable`)
every record of the member that is neither in `kept` nor reached by a walk it completed (the
missing header could have reached any of them), never as not kept. A record that cites the
revocation seq or later is refused `revoked` whatever the walk says (§11.5 step 3). The approver's host computes `kept` and `heads` from every record it holds, including
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
| `services` | 1–64 entries, distinct audiences. `audience`: an `https://` URL (host by the `rp` grammar, optional path, no port, query, fragment or user information) or a `urn:` URI, 1–512 printable ASCII bytes (§2.2). `purposes`: `["*"]` or 1–64 distinct names of 1–128 bytes of `A–Z a–z 0–9 . _ : / -`. |
| `expires` | Inclusive last moment, a §2.2 date. Absent: no expiry. |
| `writes` | Most admitted records, counted as 0.3 §5 counts `writeBudget`. |
| `depth` | 0–4 links may follow. Absent 0. |
| `conditions` | 1–32 predicates, all must hold (§10.4). |
| `serves` | `["home"]`. Another value is unknown content (§1); a duplicate is `malformed`. |
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

- It reads a call's `args`, or a record's decrypted `payload`. A path is 1–8 dot-separated
  segments of 1–64 bytes, counting a leading `args` segment, which is then ignored; no array
  indexing; a missing path makes the five leaf predicates false.
- `eq`, `in` compare canonical bytes, so their values may be `null`; `prefix` needs two strings; `lte`, `gte` need two numbers:
  integers exactly, binary64 by IEEE-754, integer against binary64 exactly without converting the
  integer.
- Empty `all` is true, empty `any` false; `not` inverts, including a missing-path false.
- A predicate with an unknown operator is *unknown*. `not` of unknown is unknown; `all` is false if
  any member is false, else unknown if any is; `any` is true if any member is true, else unknown if
  any is. So `any:[true, unknown]` is true and the call can be `ok`. A false result is
  `refused:outOfScope` (§12.3 step 7); an unknown one passes step 7 and is `newerFormat` at step 8.
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
  the account then revokes the member (keeping every head, §9.5) and grants a new key. A
  `previous` that names no header the verifier holds does not keep the header from being
  admitted: only the §9.5 walk follows `previous`.
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

Fold order is `(clock, author, id)`, never `created`. Two headers by one author with the same
operation ID and clock (they can differ in `level` or `previous`, which the ID does not cover)
are ordered by body digest, lowest first, so the verdict is a function of the set held; the second
to authenticate is `duplicateID` (0.3 §5). Clocks are positive integers at most
2^53−1; a writer increments past the highest admitted clock in the namespace; an otherwise
admissible header more than 1,024 above the highest earlier admitted clock is refused `clockJump`.

### 11.5 Admission

After the header's signature, account binding, format and path:

1. Author is a member with a `records` entry for the namespace covering `level`, at the verified
   authority (the member's grant as it stands at the seq the header cites, so a cite before the
   grant is `notGranted`; the latest verified state for a seq beyond the replica): else refused
   `notGranted`. An author that is not a
   member of the verified history is `notGranted` as well, without a signature check (there is
   no key to check one with).
2. `created` later than the member's latest verified expiry: refused `expired`.
3. Author revoked and record not kept (§9.5): refused `revoked` if it cites the revocation or
   later, else held `revokedBackdated`; walk incomplete: held `unavailable`.
4. `authority` newer than this replica, or at or after an unresolved fork: held `authorityBehind`.
5. Epoch not current at that seq: refused `wrongEpoch`.
6. Clock jump: refused `clockJump`.
7. `writes` spent by earlier admitted headers: refused `budgetSpent`.
8. Otherwise admitted; reserves one budget slot per distinct `(author, id)`.

After opening: a kind outside `kinds`, or a `conditions` predicate that is false (§10.4), is
refused `outOfScope` and still reserves its slot; one that is unknown is `newerFormat`. (A new
operator in any grant already makes the account's history `newerFormat` for an older reader at
§8.5 step 4, so three-valued conditions matter for link terms.) Missing epoch key: held `unavailable`. 0.3 §5's rules
for `invalidPayload`, `duplicateID` and unknown payload versions apply. **In an upgraded
account** a `/3` header is admitted under 0.3 §5 and 0.4 only if it cites authority before the
`upgrade` and its `library` is the legacy ID; a `/5` header cites the `upgrade` seq or later;
anything else is refused `wrongFormat`.

### 11.6 Proposals

A `propose` record is admitted like a write and not folded as one.

- `colophon.accept` and `colophon.decline` have payload `{"proposals":["<operation ID>", …]}`
  (1–64). Each is a `write` record in the proposals' namespace and resolves a proposal only if
  its author may `write` the proposal's kind and **its clock exceeds the proposal's**. A resolution
  is a record of its own kind, so a resolver whose grant lists `kinds` for the namespace MUST list
  `colophon.accept` and `colophon.decline`, or its resolution is refused `outOfScope`: there is
  no implicit right to resolve.
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
  identical body are identical (200; a relay MAY keep the first it stored, but a verifier judges
  every envelope it holds and its verdict never depends on which was stored first, §2.2), and only
  a different body is 412.
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
`session` only on the first link. `notBefore` ≤ `expires`, else `malformed` (§12.3 step 1);
`expires` ≤ `notBefore` + `policy.linkMaxAge`, else `refused:expired` (step 6). A link's `created`
is informational: it carries no rule, is compared with neither `notBefore`, `expires` nor any
clock, and no verifier refuses a link for its value (it must still be a well-formed date).

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

Signed `raw` by `key`, or with `assertion` by a WebAuthn controller. A member's call with an
`assertion` is `malformed`; a controller's call whose form and `assertion` disagree with its
descriptor is `badSignature` at step 5.

### 12.3 Verifying a call

A verifier MUST, in order (the pipeline of §1):

1. **Parse.** Bounds; `protocol` is `colophon/call/5` (anything else `malformed`); every embedded
   link `colophon/link/5`; every known field well formed, including each link's `notBefore` ≤
   `expires` and no `to.signing` repeated within the call. Else `malformed`.
2. **Possession.** The signature verifies under `key` (ES256 over the body, or for an assertion
   `clientData` `type`, `challenge`, `crossOrigin` and §4.3 step 5 under `key`). Else
   `badSignature`. Nothing is fetched before this.
3. **Audience, window, replay.** `audience` is one of the verifier's own (§10.1), else
   `refused:audience`. `created` within 3,600 s of the clock, else `refused:window`. A read-only
   look-up in the replay store (§12.4) refuses a recorded key: `refused:replay` or
   `refused:conflict`. It writes nothing.
4. **History.** The verifier holds a verified history of the account (none: `unavailable`)
   containing `asOf` (a different digest there is `refused:fork`) and fresh heads from at least
   `headQuorum` distinct current homes, and has fetched up to the highest of them. No homes, or
   too few fresh heads: `unavailable`. Freshness and `headQuorum` are read from the latest held
   policy. Let **S** be the highest seq covered by `headQuorum` fresh heads. `created` within
   `callWindow`, else `refused:window`. An unresolved vouched fork: `refused:fork`.
5. **Signer, evaluated at S, with removals beyond S applied.** Grants, controllers and terms added
   after S don't count. Revocations, controller removals, demotions, descriptor tightenings,
   `endSessions`, `suspend` entries and policy changes that shorten or restrict, held by the
   verifier after S, apply at once: `callWindow` and `linkMaxAge` are those at S made field by field
   stricter by every later held policy. A pending transition changes nothing until its `activate`
   entry (§8.7). Then:
   - **A controller** must pass under both its state at S and its latest held state (roles
     intersected, `verification` from either, the call meeting both descriptors' forms and
     verified under both; a form that differs can't be met, `badSignature`). A controller removed
     after S is `refused:revoked` even if re-added after S. A suspension that has ended by the
     verifier's latest held entry or clock no longer applies.
     - It must be present, not suspended, and not added by an activation with no `final` (or
       other finality, §8.7) in the history the verifier holds, else `refused:revoked`.
     - Its roles must include `approve` or `control`; or be `sign` with `audience` in its
       `audiences`; or include `recover` when `purpose` is `colophon.history.read`. Otherwise
       `refused:outOfScope`. A suspended controller is refused only for other purposes.
     - Its `signing` must equal `key`, and the call must pass all of §4.3 with its descriptor,
       else `badSignature`.
     - For an assertion, the `origin` must be exactly one of the verifier's call-ceremony origins
       for its `rp`, else `refused:origin`.
   - **A member:** it must be present, not revoked, and not added by an activation with no
     `final` in the history the verifier holds, else `refused:revoked`, and not expired at the verifier's clock (`expires` is the last
     valid moment), else `refused:expired`.
6. **Chain.** First the bindings, for every link from the member outward: it verifies under the
   previous key and has this `account` and `from`; then the acting `key` equals the last link's
   `to.signing` (no links: the member's key). Any failure: `badSignature`. Then, link by link:
   the first link's `session` equals the member's session number, else `refused:ended`;
   `notBefore` ≤ now ≤ `expires`, `expires` within the previous link's and the member's and within
   `linkMaxAge` of `notBefore`, else `refused:expired`; its terms narrow the parent's, else
   `refused:notNarrower`; its `to.signing` is no principal's point (§3.3), else `malformed`.
7. **Purpose.** For a member, its terms and every link's must allow `audience` and `purpose`, and
   no `conditions` predicate may be false on `args` (§10.4). For a controller, `purpose` must be
   among the verifier's configured purposes for controller calls; there is no generic or fallback
   purpose, except that a home always accepts `colophon.history.read`, `colophon.home.read` and
   `colophon.home.write` at its own endpoints, allowed as §13.4 and §14 say. A current member
   calling with its own key may read the history and records at a home; through links, only when
   every link's terms grant the purpose there. Else `refused:outOfScope`.
8. **Extensions.** Unknown fields, terms or values in the authenticated call, links or terms, or
   a `conditions` result that is unknown (§10.4): `newerFormat`. An unknown operator whose
   predicate doesn't decide the result (for example inside an `any` with a true member) is not
   reported.
9. Otherwise `ok`, recorded in the replay store as §12.4 says.

### 12.4 Replay store

- **Key.** `(account, audience, acting key ID, purpose, requestId)`.
- **Look-up.** Step 3 reads the store and refuses a key already reserved; it writes nothing.
- **Reservation.** After step 8 and before any effect, the verifier makes an atomic
  compare-and-swap reservation of the key, recording the body digest:
  - an existing reservation with the same digest is `refused:replay`;
  - one with a different digest is `refused:conflict`.
  A call refused at any step reserves nothing.
- **Terminal states.** A reservation ends as exactly one of `completed(result, effect)`,
  `completed(result, none)` or `abandoned`. The effect and its completion MUST commit together,
  or the effect MUST write a durable record (call digest, effect identity, replayable result)
  under the key in its own transaction.
- **Crash recovery.** A reservation left pending is resolved from that record: to completed if the
  effect committed, otherwise to `abandoned`. It is never resolved by re-running the effect.
- **Later identical calls** are `refused:replay`. An audience MAY return the recorded result of a
  non-read purpose to the same acting key.
- **Sharing and retention.** The store is shared by every instance serving the audience. A
  reservation is kept while `now − reservedAt ≤ 7,260 s` (more than twice the 3,600 s window of
  step 3, plus 60 s of clock skew), so no call it guards can be accepted again.
- **Rate.** A store MAY rate-limit keys with `refused:window`.
- **Records.** `ok` is not a record in the account. A service that acts on a call writes records
  under its own member key, with a `basis` naming the call's digest.

## 13. Homes and heads

### 13.1 Homes and the primary home

A home is a member with `serves: ["home"]`, appointed by a transition, and counts as a home once
that activation is final (§8.7). Any server, device or service the owner chooses can be one. A
home stores only entries, transitions and vetoes that verify `ok`, and holds no controller or
member private key, PRF output or seed. An account appoints up to 8 homes.

- **Ordering.** Immediate entries go first to the primary home (`policy.primaryHome`, else the
  earliest-appointed current home), which stores the first valid entry per seq. Other homes store
  them once a primary head covers them.
- **Transitions.** Every home receipts and forwards transitions, vetoes, receipts and its heads
  to every other current home, and appends recording entries (§8.7), whatever the primary does:
  `activate` once due, `vetoed` once a veto is valid, and `final` as soon as it holds the witness
  heads, before storing anything signed or receipted by what the activation added. A home that
  holds a valid veto MUST NOT store that transition's `activate`. A home stores an `activate` for a
  transition it didn't receipt only if it first saw the transition, or a receipt of it forwarded by
  another current home, within 300 s after the transition's `issued`, or it was not serving for any
  part of that window. Otherwise it refuses that `activate` for ever and notifies the controllers,
  and it **still stores and serves the transition and its receipts** (§14), so the owner can veto
  it before its deadline; a late transition with a valid veto is vetoed like any other. A veto that
  reaches a home more than 300 s after its `issued` is stored and served when it comes with at
  least one receipt of it from another current home that is in window (§13.5) and that the home
  already holds, as a forwarded transition is; the home signs no receipt of its own for it.
  Without such a receipt it is `refused:late` and not stored. A home
  persists, per object, when it first saw it, its own serving intervals over the object's window,
  and its decision, and reuses that decision after a restart.
- **Clock.** A home refuses an entry more than 60 s ahead of its clock (`refused:early`), and an
  immediate entry or a full set whose `issued` is more than 300 s behind it (`refused:late`). So at
  an honest primary an immediate entry's `issued` is its admission time to within 300 s.
- **Admitting pending objects.** A home receipts a transition when, against its latest state, the
  transition meets §8.7's validity except receipts, its delta is not void, and its clock is between
  the transition's `issued` and 300 s after it. Admission under a full cap is local and depends on
  arrival, by design: a full home refuses and never evicts, and two homes may admit different
  transitions. What is deterministic is the checking order below, the named result, and that
  validity never depends on which home admitted what, only on receipts reaching `headQuorum`.
  Hosts refused at one home retry at the others.
  1. each `control` or `recover` unit may have at most 2 pending transitions it proposed
     (`refused:proposerFull`); the proposer is the unit of the primary signer (`by`), and
     cosigners are not charged;
  2. the account may have at most 2 pending transitions per such unit, so no set of proposers can
     take another unit's share (`refused:pendingFull`);
  3. a transition may have at most 8 vetoes, at most one per vetoing unit (`refused:vetoFull`).

  A home checks the clock first (`refused:early`, "Clock" above), then these caps in this order.

  A hostile home at `headQuorum` 1 can still receipt a transition, hide it from its listing, and
  reveal it only in its `activate` after the deadline; then nobody can veto it. That is why quorum
  1 doesn't resist a hostile home (§18).
- **Rate.** For each immediate entry E (every kind except `genesis`, `upgrade` and recording
  entries), its **charged signer** is its `by`, or, when `by` was added by an immediate `keyring`
  entry, that entry's charged signer. Over E and the immediate entries **preceding E in the
  sequence** with `issued` in the 24 hours ending at E's `issued`, those charged to E's charged
  signer MUST NOT exceed `policy.rate.signer`, and those of the account MUST NOT exceed
  `policy.rate.account`, in entries and in body bytes; `revoke`, `endSessions`, `rekey`, `vault`
  and `suspend` count toward the signer limit only. Every verifier and home refuses an entry
  exceeding either as `malformed` (§8.5). A verifier checks the window over `issued`; only a home
  can check that `issued` is the admission time (the clock rule), which is what stops a dormant
  account's history being filled in one sitting. A hostile primary can still admit backdated
  entries (changes §H). Transitions and vetoes are bounded by the admission caps above.
- **An account with no home has no witness of time or order.** Everything on it is final at
  once, on every branch alike, so a former controller can show a **new** verifier a different
  history from before its own removal (a late entry at an old seq and a `resolve` keeping it),
  and nothing in the objects can tell the two apart. This is a limit, not a defence (§8.6, §8.7
  "No home"). A verifier with persisted state whose high-water entry is not on the branch it would
  now follow reports `refused:rollback`, and a host MUST treat that as a refusal and show it. Hosts
  MUST create accounts with at least one home by default (§18) and MUST warn when an account has
  none.
- **Honest bulk work** fits the defaults: a first import is records, not authority entries;
  onboarding twenty people is twenty grants. A clean copy with more than 64 members to re-admit
  needs a second approver or a day's pause (§15.3), or a transition raising `rate`.
- **Notices.** On receipting a transition, a veto or a `suspend`, a home MUST push a notice to
  every delivery route registered with it, and MUST support at least one out-of-band route (for
  example e-mail) the owner configures (§17.5). A notice has no signed body and no wire format in
  0.5: it is home and host behaviour over the routes registered at setup, and nothing in this
  document defines a notice object.
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
`issued` is at most 60 s ahead of the clock (else `unavailable` until it is); and the verifier's history, fetched further if
needed, contains `authority.seq` with that digest (a different digest: `refused:fork`; fetch
failure: `unavailable`). A head is **fresh** while `now − issued ≤ policy.headMaxAge`. A head that
is not fresh is never used as evidence of the current state. Heads embedded in a `final` entry are
verified as §8.7 says (the home's key in the state before the activation, freshness not needed).

- **High-water mark.** A verifier persists per account its highest accepted `(seq, digest)` and
  the folded state there, and **per home** the highest `(seq, digest)` of a head it accepted from
  that home. It only detects rollback: a history that stops before the account's seq, or a head
  behind its home's mark, is `refused:rollback`. A head is judged behind its home's mark only
  while the marked entry is still on the verifier's history; if a displaced provisional
  activation (§8.7) took it off, the mark names another branch and a lower head is no rollback.
  A head is checked for its signature, clock and held history first (`refused:fork`,
  `unavailable`), then against the mark. It never selects a branch: a conflict is decided by §8.6
  from the objects held, including the entries the verifier keeps, so a verifier that saw one
  branch first reaches the same verdict as one that saw the other.
- **Incremental verification.** A verifier MAY resume from its persisted state: it fetches entries
  after its high-water seq, checks the first one's `previous` against its persisted digest, and
  verifies each under §8. A verifier with no persisted state MUST fetch and verify the complete
  history from seq 1, in pages; it MUST NOT accept a suffix it can't link to a state it verified.
- **Quorum.** Heads from different homes are compared by ancestry: a lower seq is behind, not
  wrong; divergent histories are a fork.
- **Equivocation.** A verifier holding proof that a home misbehaved MUST keep an evidence object,
  MUST stop counting that home for this account, and SHOULD send the evidence to the account's
  controllers. Every form is judged against the account's history the verifier holds, and
  none is checkable from the keys it names alone: what a verifier needs to hold is stated per form.
  - **Heads:** `{"protocol":"colophon/equivocation/5","account","heads":[…]}`, two heads by one
    home with the same `seq` and different digests, sorted by body digest. Let h1 be the head
    with the earlier `issued` and h2 the later. Follow the two covered entries back to the seq
    where their branches first differ. If §8.6 rule 1 decides that divergence (a recording entry
    against another entry) and h2's entry is on the side that stands, it is **not** equivocation,
    at any seq at or after the divergence: an honest home signs over an entry and later over the
    one that displaced it. If the two `issued` are equal and the divergence is a rule 1
    displacement, it is not equivocation either. Otherwise it is. The verifier needs the
    history, and both entries, back to the divergence; without them the answer is `unavailable`,
    never a conviction. A home MUST give its heads strictly increasing `issued` (§13.3 below).
  - **Entries:** the same with `entries` in place of `heads`: two signed entries with the same
    `seq` and `previous` and different digests, each valid in its place (§8.5). It convicts
    their signers: exactly the signer units present on both entries. A recording entry has no
    signer and convicts nobody, so an `activate` against an ordinary entry is §8.6 rule 1, not
    evidence. Where §8.6 rule 2 asks for head evidence, the heads are held as well.
  - **Veto against a final activation** (§8.7):
    `{"protocol","account","activation","veto","receipt","final"}`: the `activate` entry (which
    embeds the transition and its receipts, so the veto's deadline can be computed), the veto
    envelope, the home's receipt of the veto, and the `final` entry whose heads include that
    home's. The verifier needs the history up to the activation, to judge the veto's signers
    and the home's key in that state.
- What freshness gives, and doesn't, is explained in the guide §3. A brand-new verifier fetches
  the history from any source, verifies it from seq 1, asks every home the history names, and
  applies §12.3 step 4.
- A home SHOULD sign a new head at least every `policy.headMaxAge` / 2 and MUST NOT sign a head for
  an entry it hasn't verified. It MUST give its heads strictly increasing `issued`, and MUST NOT
  sign a head for a second digest at a seq unless its own verdict shows the first displaced under
  §8.6 rule 1 (the entries' branches first differ at a seq that rule decides, in favour of the
  second head's side; the Equivocation rule above). The guard belongs to home admission, which holds the history: the host
  that drafts a home's head calls the home's guard first and signs only what it passes (in the
  reference core `HomeState::guard_head` returns a token that `prepare_head` requires, so a head
  cannot be prepared for signing without it). A home keeps only what the guard needs: the latest
  `issued` and the digests at seqs not yet settled by a final activation.

### 13.4 Who may read the history

`policy.history` `public`: anyone. `members`: callers presenting a valid call with audience a home
endpoint and purpose `colophon.history.read`, signed by a controller holding `approve`, `control`
or `recover` (suspended or not), by a `sign` controller listing that audience, by any current member, or under terms
granting that purpose there. The head is always public. This governs every path serving the
history, transitions, vetoes and receipts, including `records/authority/*` on a relay that is a
home.

### 13.5 Receipt

```json
{"protocol":"colophon/receipt/5","account":"<64 hex>","object":"<body digest>","received":"…","by":"<home member ID>"}
```

Signed `raw` by a home's member key for a transition, a veto or a successor genesis, and stored
beside it as `<home member ID>.receipt.json`. A home signs at most one receipt per object, and
only while its clock is between the object's `issued` and 300 s after it. It is valid when:

- `by` is a current home in the state the verifier evaluates, not one added by a provisional
  activation;
- `object` is the receipted body's digest;
- `received` is not earlier than that body's `issued` and not more than 300 s after it. For a
  successor genesis, the window is the succession window instead (§15.1).

## 14. Exchange

A home is a relay (0.3 §8) whose `GET {base}` response adds `"home":{"member":"<ID>"}`. At
`{base}`:

| Request | Response |
| --- | --- |
| `GET {base}/head` | 200 latest head envelope; 404 if none. Public, `no-store`. |
| `GET {base}/authority?after={seq}&limit={n}` | 200 `{"entries":[…],"receipts":[…],"more":bool}`, 1–64 entries from `after + 1`, under §13.4. |
| `POST {base}/authority` | `{"from":<seq>,"entries":[…],"receipts":[…]}`, 1–64 contiguous entries. 200 `{"head":…,"receipts":[…]}`; 409 with the current head if `from` overlaps different bytes or leaves a gap; 422 with the §1 result; a non-primary home answers 421 with the primary's endpoints for an entry no primary head covers. No other authorization is needed. |
| `GET {base}/pending?after={cursor}&limit={n}` | 200 `{"objects":[{"seq":<cursor>,"digest","kind","envelope"}…],"more":bool}`: 1–64 pending objects in the order the home first stored them, after `cursor` (0 to start). `kind` is `transition`, `veto` or `receipt` (a receipt by any current home). Cursors are the home's own increasing integers and never reused. Under §13.4. |
| `GET {base}/pending/{digest}` | 200 `{"envelope","receipts":[…]}` for a pending transition or veto with every receipt the home holds for it; 404 otherwise. Under §13.4. |
| `POST {base}/pending` | `{"objects":[…]}`, 1–16 transition, veto or receipt envelopes. 200 `{"receipts":[…]}` with this home's receipts for those it receipted; 422 with one result per refused object: the §8.5 result, or `refused:early`, `refused:late`, `refused:proposerFull`, `refused:pendingFull` or `refused:vetoFull` (§13.1). No other authorization is needed. |

**Pending objects.** A home lists every transition and veto it stores that has no recording entry
on its branch, and every receipt of them, until 7 days after the transition's due time; then it
MAY drop them. One object appears once in a listing; a listing from cursor 0 until `more` is false
is complete for the moment it ends. The admission caps (§13.1) bound a listing at 128 transitions
(2 for each of at most 64 units), 8 vetoes each and one receipt per home per object: at most
10,368 objects. Hosts poll with `after` set to the last cursor they saw (§17.5). Reading
follows §13.4, which includes recover-only and suspended controllers.

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
  predecessor (§8.7). After it, while F is provisional, the predecessor admits only
  these entries: F's own `final`; a `final` that Order (§8.7) requires first for an earlier
  activation that is not removal-only; a `vetoed` that displaces F (§8.6 rule 1: a candidate at F's
  seq, which lets the predecessor continue); and the entries of a removal-only revocation of a
  home, its `activate` and its `final`, so that a dead or hostile witness cannot freeze the
  predecessor for ever: once that revocation is final the home is excused for F (§8.7), exactly as
  for any other activation. A `final` of an earlier removal-only activation is not among them.
  Every other entry is `malformed` evidence. Once F is final the account admits nothing (§15.2).
- For Swift it is the freezing `layout` entry (§16.3). Swift has no pending entries, so the
  waiting happens in the successor first:
  1. **Handover.** The genesis carries `handover`: signatures over the genesis body by the keys
     that may write F at `head` under §16.3. For a root library that is the current root; for a
     keyring library, the control threshold, plus `recoverThreshold` recover keys when the
     genesis changes the recover set or lowers that threshold. `handover` MAY carry further keys
     current at `head`, and hosts SHOULD include every such key they can obtain, because each
     raises the number of keys a veto needs. `handover` signatures are authority signatures with
     the genesis descriptors' origins.
  2. **Window and due time.** The **succession window** is the 300 s after the `issued` of the
     first successor entry that leaves it with `headQuorum` current homes (normally the first
     upload's `activate`, §13.1). The homes current at that entry receipt the genesis within the
     window (§13.5). The succession is due at the window's end plus the `recoveryDelay` in force
     at that entry, provided `headQuorum` of those homes receipted it; its veto deadline is 300 s
     before that.
  3. **Vetoers.** Let W0 be the `issued` of the succession window's entry, which the homes
     witness (they receipt the genesis only within 300 s of it and refuse it more than 300 s
     behind their clocks). The genesis `issued` MUST NOT be earlier than `head`'s `issued` nor
     later than W0 (`malformed`). Until the veto deadline the succession may be vetoed by any key
     current at **any instant** from W0 minus that `recoveryDelay` through `head`: in the state
     after the last predecessor entry issued at or before that instant, and in the states before
     and after every later predecessor entry, taking each entry's time as the latest `issued` of it
     and the entries before it. Also by any key current immediately before the last predecessor
     entry that replaced the root or recovery identity or removed a controller. A veto needs as
     many keys as `handover` has signers. **Limit:** Swift entries' times are the signer's own, so
     a root thief in a library quiet for longer than the delay can date his rotations before the
     window; the owner's defence there is a `handover` with more keys and hosts that show the
     predecessor's last entries before the person confirms (changes §H).
  4. **Recording.** A successor home that holds a valid veto MUST append a `successionVetoed`
     entry (unsigned, determined): `by` is the veto's `by`; `issued` is the later of the latest
     chosen veto receipt's `received` and the preceding entry's `issued`; `veto` is the veto
     envelope (§8.7), whose `transition` is the genesis body digest; `receipts` are its chosen
     receipts (§8.7) by homes current at the window's entry, each `received` within 300 s of the
     veto's `issued` and before the veto deadline; `genesisReceipts` are the genesis's chosen
     receipts. Each veto signer must be an eligible key of step 3, verified under its predecessor
     descriptor (§16.3: `rpID` as `rp`, the general origin rule, UV). An account has at most one
     such entry; it is ordered by §8.6 rule 1 with the succession's due time and bounded in time
     like a `vetoed`. After it the succession is never verified and no `migration` activates.
  5. **Write F.** F is written only after the due time.
  - A root library's hand-over is signed by the root alone (rationale: guide §7).
- **Published** at the predecessor's own homes (`/5`), or at the successor's homes under
  `{base}/predecessor/` (Swift).

**Chain bound.** A `/5` predecessor may itself be a successor, so a verifier follows the chain
through each genesis: the claimed account, then the account its genesis names as its predecessor,
and so on. It follows at most 16 accounts; a longer chain is `malformed` (§2.4). Objects in the
supplied set that are not on this chain, such as an unsigned or unrelated genesis, are ignored and
never change the verdict.

**Verified** when:
- the verifier holds the predecessor history through F;
- F names this account;
- for `/5`, F is final (§8.7), by a `final` on the predecessor's branch or by excusal: a provisional
  F verifies nothing, and a `vetoed` that displaces it ends the succession attempt;
- the history has no fork at or before F;
- the succession was due before F;
- for Swift, fresh heads issued after the due time by every successor home current at the
  window's entry cover a successor history with no `successionVetoed`. A home that signed such a
  head while holding a valid veto misbehaved (§13.3).

**Competing attempts.** A Swift predecessor's final entry is the first freezing entry whose
succession is verified. A freezing entry whose succession isn't verified (premature, vetoed or
never due) doesn't end the predecessor: the owner may make a new attempt and write a later freezing
entry (a higher layout) after it. The predecessor's sequence orders freezing entries, so there is
no tie. A verifier that has persisted a verified succession keeps it. Any entry after the final
entry is `malformed` evidence. A predecessor confers nothing: no member, grant or key comes from
it.

### 15.2 Successor

After the activation of a `successor` transition is final, the account accepts no further entry;
later entries are `malformed` evidence. While it is provisional the account admits only the
entries that settle it (§15.1). The old account stays readable. A verified succession can't be undone.

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
(§16.2), or stop and say why. Re-admitting members is one grant each, charged to the approver
(§13.1): more than `rate.signer.entries` of them in a day needs a second approver or a pause. The
tool tells the person that publishing the predecessor discloses its history to the new homes'
operators. Records arriving after the window stay in the frozen predecessor;
hosts show them as left behind, with an action to copy them.

### 15.4 Migration entry

The `migration` change of a transition (§8.7), at most once per account, only in an account
whose genesis has `predecessor`:

```json
{"migration":{"predecessor":{"format":"…","account":"…","final":{"seq":13,"digest":"<64 hex>"}},
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
public keys (same passkeys, security keys, device keys and kit, same key IDs) with `authorityOrigins`
on each `webauthn` controller. **No new account at any service and no new passkey.**
- **Roles carry over exactly.** A keyring library's controllers keep their roles and thresholds.
  A root library's root becomes `approve` + `control` and its recovery identity `recover`; its
  stewards are carried as `recover` controllers only if the person chooses, because 0.5 has one
  recovery threshold. The shipping apps give security keys `control` and the passkey `recover`,
  the reverse of §18's reference for new accounts; the tool does not guess which the owner means.
  Changing roles afterwards is an ordinary pending transition the owner chooses (§8.7), and hosts
  SHOULD explain the reference and offer it.
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

**Historical encodings.** Predecessor signatures use §4.3 step 5 exactly, with no lenient form
(`r` or `s` of zero is refused); this matches what CryptoKit accepted on macOS 27 (candidate
README).
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

**Steward threshold.** `threshold` is an optional integer field of every Swift entry
(`AuthorityEntry.threshold: Int?`). On a `genesis` or a `stewards` entry, absent or `null` is 0
(`AuthorityState`: `genesis.threshold ?? 0`, `entry.threshold ?? 0`), and a `quorum` `handover`
needs `threshold > 0` as well as that many distinct steward signatures, so a threshold of 0 (or a
negative one) lets no quorum hand the root over. Swift reads a string, a boolean, an array, an
object or an integer beyond 64 bits as a decoding error, and its decoder would also accept `2.0`,
`1e1` or `2E0` as integers. Shipped Swift writers always write plain integers, so a 0.5 verifier
refuses any other number form for `threshold` in a predecessor, on every entry kind, as
`malformed`. This reading has not been replayed by the Swift source.

**Quorum handover.** Swift counts the distinct stewards whose key verifies the primary signature
or any cosignature, and ignores every other signature: extra, duplicate, mislabelled or from a
non-steward, provided enough stewards verify (`AuthorityState.swift`, the `quorum` case). A 0.5
verifier refuses a quorum `handover` that carries such a signature: it needs every signature to
verify under a steward, each steward once, and the primary signer to be one. The shipped apps
never write a quorum `handover`, so no existing library is affected.

**The freezing entry.** F is a `layout` entry with `layout` greater than 2 and an extra field
`successor` (the 64-hex 0.5 account ID), signed under the rule in force (root before adoption, the `layout` rule
after). Released Swift readers verify it and then stop with `unsupportedStorageLayout` (those
that predate `layout` stop with `newerAuthority`); they never write after it. A verifier of a
predecessor reads `successor` from F's body.

## 17. Host interface

### 17.1 Core and host

The core prepares every body the host signs (entries, transitions, vetoes, `suspend`, links,
calls, heads, receipts) as exact bytes, and verifies §4 and §8 before returning a record; nothing
is written on failure. New PRF slots need PRF before the body (§7.2).

**The seed.** The core never returns seed bytes or a raw ECDH output through its interface. An
opened seed can be sealed only to controllers of its own account's verified keyring (slots), to
a new vault the host creates at a rotation, or to a device the person confirmed by pairing
(§7.4). The host is trusted with the seed during rotation and transfer: it supplies the
entropy of a new vault and performs the scan or code comparison.

**Restricted open.** The host alone may ask the core to open an HPKE seal to the vault for its
own registered formats. The seal is `{"enc","ciphertext"}` as §11.1 (`enc` a valid 65-byte
uncompressed P-256 point, `ciphertext` 16 to 65,536 bytes); `info` equals the AAD and is at most
1,024 bytes. An `info` that begins with `colophon/` belongs to the core's own labels and is
refused `refused:outOfScope`, whatever the seal holds. The host interface and the history verifier's report are described in
[colophon-0.5-guide.md](colophon-0.5-guide.md) §4.

### 17.2 Persisted verifier state

A verifier that resumes (§13.3) MUST persist, per account, atomically and with a format version.
Every item except the head marks is a function of the history and the objects held, recomputed
identically by replay from seq 1, so two verifiers that persist it reach the same verdicts:
- the high-water `(seq, digest)` and each home's head mark (rollback detection only, §13.3) and
  the folded state there. **Head marks are local memory:** no replay of the history recomputes
  them, since they record what this verifier accepted and when. They survive a checkpoint format
  change by being carried over when the checkpoint is rebuilt from the retained objects, and a
  checkpoint whose marks are malformed is refused. Everything else listed here is recomputed: keyring, members (terms, expiry,
  session number, revoked seq), homes in appointment order, policy, epochs, and whether the vault
  is retiring;
- the digests of transitions with an `activate` or `vetoed` on the branch, and the forks a
  `resolve` activation on it kept (`seq`, `digest`), and the activations that homes witnessed;
- each activation not yet final, with its witness set and whether it is removal-only; the
  `final` entries; the homes excused by final removals;
- v(u) per unit and, per unit, the seq of its last compliant activation;
- each outstanding suspension: key, suspending unit, the transition with its chosen receipts, and
  its due time;
- the immediate entries of the last 24 hours of `issued` with their charged signers and sizes;
- entries held (future `issued`, an `activate` not yet due);
- the exact bytes of transitions, vetoes and receipts held outside the history, with each object's
  receipts per home;
- signed entries displaced by §8.6 rule 1 and not yet re-signed;
- the latest fresh head per home, equivocation evidence and the homes it no longer counts, and
  unresolved conflicts;
- a verified succession, if any.

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

A notice is not an object of this specification: it has no signed body and no wire format in 0.5.
It is behaviour of homes and hosts over the delivery routes registered at setup (§13.1), and
nobody should build a signed notice object. The mechanism is only as safe as people's
knowledge of pending transitions, so:

- **Routes.** At setup, hosts MUST register at least two delivery routes with every home, on
  different devices or services (for example push to a second device, and e-mail).
- **Polling.** Every host holding a controller key MUST list pending objects (§14) at every current
  home at launch and at least every `recoveryDelay` / 6.
- **Showing.** It MUST show each transition it hasn't shown, with its signers' labels, key IDs and
  first-seen seq, its veto deadline, and a one-tap **veto**.
- **Missed notices are visible afterwards.** Whenever a person uses any key with any host, the host
  MUST first show every activation since that host last showed the account's history that no key
  on this device signed and the person hasn't seen, with when each home receipted it. A recovery
  key is no exception: a person whose only device was stolen learns of the thief's transitions the
  next time they use any recovery key with any host.
- **Submitting.** Hosts MUST submit every transition, veto and `suspend` to every current home
  directly, and retry until each has receipted it or 300 s have passed; and publish entries to the
  primary home and then every home.
- **Removal follow-up.** When a controller's removal activates, hosts MUST list every member whose
  grant it signed, and every `approve` or `sign` controller it added by immediate entries, since
  that transition's anchor, that the removal didn't already remove, and offer to remove them in
  one action.
- **What to tell people.** Hosts MUST say, when an account is set up with one device, that a
  stolen sole device can't veto, and in every notice that the delay protects who controls the
  account, not data a stolen key could already read (wording: guide §5).
- **Quorum 2.** At `headQuorum` ≥ 2, a transition that fewer than `headQuorum` homes receipt within
  300 s of its `issued` is dead; hosts MUST say so and offer to sign it again.
- **Testability.** These are host requirements with observable behaviour, tested with a simulated
  home (§21).

With two routes and missed notices shown afterwards, the default delay stays 72 hours.

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
| `policy.headMaxAge`, `callWindow`, `linkMaxAge` | 300 s, 300 s, 86,400 s | §6.3 | lowering immediate; raising by transition |
| `policy.headQuorum` | 1 | 1–8, at most the homes | transition with consent |
| `policy.history`, `memberRule` | `members`; `single` (person), `control` (company) | §6.3 | tightening immediate; loosening by transition |
| `policy.primaryHome` | absent | a current home | transition with consent |
| `policy.rate` | signer 64 entries / 4 MiB, account 256 / 16 MiB, per 24 h | §6.3 | lowering immediate; raising by transition with consent |
| Member `expires`, `depth` | 7 days and 1 for `agent`; none and 0 otherwise | §10.1 | approver; `renew` extends |
| Homes | **two, run by different operators (one may be the owner's own machine), before any recovery key; a host MUST create every account with at least one and MUST warn when an account has none (§13.1: without a home there is no witness of time or order)** | 0–8 | transition with consent |
| Drain window | 7 days | 0–30 days | the copying host |

**Reference setup for new accounts:**

| | Person | Company |
| --- | --- | --- |
| Control keys | each device's owner key, and one passkey per platform or password manager, `approve` + `control`; **at least one control key not on the phone** (for example a computer's device key) | each founder's device keys and passkeys, `holder` the founder |
| Recovery keys | two security keys, **`recover` only**, `prf` slot where delivered, **kept apart** | two per founder |
| Other | a kit or device key not tied to any one domain | the same per founder |
| Homes | two, `headQuorum` 1 | three, `headQuorum` 2 |
| Counting | `keys`; thresholds 1, 1, 1 | `holders`; `threshold` and `recoverThreshold` 2 of 3; `memberRule` `control` |

A person with only a phone can't keep a control key off it: hosts SHOULD offer one security key
with `control` + `recover` and one with `recover`, so a phone thief doesn't hold the whole control
set.

**Upgraded accounts** keep their roles exactly (§16.1, §16.2). Hosts SHOULD show the reference
and offer the role change as an ordinary pending transition.

A paragraph a host can show the person, and what the reference protects, are in the guide §5.
**Two homes at `headQuorum` 1 keep working with one down but don't resist a hostile home:** it can
hide a transition until its deadline has passed (§13.1), and with one stolen key it can win. They
are the person reference for availability only. The setup that resists one hostile home is three
homes at `headQuorum` 2, the company reference; hosts SHOULD offer it to people too.

## 19. Results and reasons

| Where | Reasons |
| --- | --- |
| Authority (§8) | The one table in §8.5; `refused:fork` (§8.6) |
| Slots (§7) | `refused:vaultLocked` |
| Records (§11.5) | `newerFormat` (an unknown condition result); refused `notGranted`, `expired`, `revoked`, `wrongEpoch`, `clockJump`, `budgetSpent`, `outOfScope`, `invalidPayload`, `duplicateID`, `wrongFormat`, `budgetScopeUnavailable`; held `revokedBackdated`, `authorityBehind`, `unavailable` |
| Evidence (§8.6, §15.1) | equivocation evidence; `malformed` entries after a final entry |
| Transitions (§8.7) | pending, due, vetoed, activated (provisional or final), void |
| Calls (§12.3) | `refused:audience`, `refused:window`, `refused:replay`, `refused:conflict`, `refused:fork`, `refused:revoked`, `refused:expired`, `refused:ended`, `refused:notNarrower`, `refused:outOfScope`, `refused:origin`; `unavailable` |
| Heads (§13.3) | `refused:fork`, `refused:rollback`; `unavailable` |
| Succession (§15) | `refused:fork`; unverified claim |

After §1 step 1, any failure verifying an attached signature is `badSignature`, with the failed
check as an optional diagnostic.

## 20. Versions

**Versions.** 0.5 accepts exactly these markers: `colophon/authority/5`, `/request/5`, `/link/5`,
`/call/5`, `/head/5`, `/receipt/5`, `/transition/5`, `/veto/5`, `/equivocation/5`,
`/operation/5`, `colophon/pair-qr/5` (the QR payload, §7.3), the legacy markers of an upgraded account (`colophon/authority/4` through its `upgrade`, `/3` records citing before it),
`colophon/relay/3`, and `colophon/swift-keyring/2` for predecessors. A verifier MUST NOT read a
0.5 account under 0.4 rules, and MUST NOT accept a `/3` or `/4` object where §11.5 or §16.1 fences
it out. A later version that adds markers will say which 0.5 markers it retires and how an account
opts in by an authority entry; until an account does, 0.5 markers stay valid for it.

What is not in this version is listed in the guide §6.

## 21. Conformance and freeze

0.5 freezes only when all of these are done:

1. **Vectors.** Every required vector (below) is published under `conformance/0.5/`, with exact bytes and
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

**Required vectors.** The list in [conformance/0.5/candidate/README.md](../conformance/0.5/candidate/README.md)
"Required for freeze" is normative for condition 1.

## 22. Review log

The reviews and their resolutions are listed in the guide §8 and mapped in changes §G.
