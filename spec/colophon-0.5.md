# Colophon 0.5

**Status: final candidate for review, 2026-11-11.** Not frozen, not implemented, not
released, and no version number has been changed anywhere. It becomes normative when it is
accepted, its §21 vectors exist and an implementation passes them. The record of what changed
from 0.4, why, and how an existing library upgrades is
[colophon-0.5-changes.md](colophon-0.5-changes.md). The work to implement it is
[colophon-0.5-implementation.md](colophon-0.5-implementation.md).

**What it replaces.** This document is complete for every format it names. It replaces
[colophon-0.4.md](colophon-0.4.md) and [colophon-0.4-keys.md](colophon-0.4-keys.md), and the
parts of [colophon-0.3.md](colophon-0.3.md) that those kept. Four parts of 0.3 are host and
engine mechanics, not identity or authority formats, and are incorporated here by exact
reference with the substitutions in §11.8: live playback state (0.3 §5.1), domain modules and
the ledger (0.3 §6), the verified-prefix cache and import/blob extension (0.3 §7), and the HTTP
relay profile (0.3 §8). Nothing else in an older document is normative for 0.5.

MUST, MUST NOT, SHOULD and MAY are requirements on a conforming reader or writer. A MUST is
not met by a host that skips it for convenience.

## 0. What an account is

- **An account is a keyring.** A person, a company or a project is an account. Its identifier
  is the digest of its first authority record, so it means the same thing everywhere, before
  any server has heard of it, and it outlives every key, device, server and app.
- **Controllers hold authority.** A controller is a passkey, a security key, a device owner key
  or a recovery kit, with roles (`approve`, `control`, `recover`). How many are needed for each
  kind of change is a setting of the keyring, with a default (§18).
- **Members do the work.** Apps, devices, agents and servers are members with **grants**: a
  signed, scoped, expiring permission from the account to a key. A member is never a
  controller. No key serves two principals in one account, so an agent can never change who
  controls the account.
- **One key may serve many accounts.** A passkey may be a controller of a person's account and
  of a company's. One person may hold many keys and many accounts. The format knows no "work"
  or "personal" identity.
- **Data belongs to the owner.** Records are encrypted to the account's vault and to members
  that may read. Any software that holds a copy and a grant reads the same data. Nothing in the
  format binds an account to a server, a deployment or a web origin, except the relying-party
  ID that WebAuthn itself attaches to each passkey (§3.2, §4.3).
- **Short sessions speak for members.** A member can pass part of its grant to a short-lived
  key through a signed **link**, and that key signs **calls** to services (§12). Sessions never
  appear in the account's history and never author records.
- **Homes keep and vouch for copies.** A home is a member appointed to keep the account's
  history and sign **heads**, statements of the latest entry it holds (§13).

**Words.** 0.4's *library* is an *account* here; "library" remains the word apps may show.
*Principal*, *controller*, *member*, *vault*, *slot*, *epoch* and *grant* keep their 0.4
meanings. New words: *terms*, *link*, *call*, *home*, *head*, *policy*, *upgrade*,
*predecessor*.

## 1. Results

Every check in this document ends in exactly one of:

| Result | Meaning |
| --- | --- |
| `ok` | Accepted. |
| `malformed` | The bytes or structure break a rule here. |
| `badSignature` | A required signature, assertion, threshold or key binding failed. |
| `newerFormat` | Authenticated content this reader doesn't know. The reader stops and asks to be updated. |
| `unavailable` | Something needed (history, a fresh head, an epoch key, a record) could not be obtained. It is never evidence that the thing is absent, valid or invalid. |
| `refused:<reason>` | Well-formed and authentic, but not permitted. Reasons are listed where they arise. |
| *held* | Records only (§11.5): kept and retried, not folded. |

**The verification pipeline is normative everywhere:** bounded generic parse; bind the
account and the claimed signer; verify every signature, threshold and key binding; check
authorization; and only then interpret unknown fields, kinds or values. Unknown content that
is not yet authenticated never yields `newerFormat`: the object fails with whatever the
earlier steps find, or with `malformed` if they find nothing. A failure at an earlier step
always wins over a later one.

## 2. Encoding and parsing

### 2.1 Canonical JSON

Every signed body is the UTF-8 encoding of one JSON **object**, so its first byte is `{`
(0x7B). Writers encode with object keys sorted recursively by their UTF-8 bytes, no
insignificant whitespace, slashes unescaped, non-ASCII characters written as UTF-8 rather than
escaped, and the minimal escapes JSON requires. Numbers follow 0.3 §2 exactly (the serde_json
1.0.145 writer with Ryū formatting): integer tokens within the signed or unsigned 64-bit range
in decimal without leading zeros; other numbers as IEEE-754 binary64 with correct rounding,
written as the shortest round-tripping decimal; `1` and `1.0` are different bytes; non-finite
numbers are forbidden. **Readers verify the exact received body bytes and never re-encode
them.** Where this document says a body MUST be canonical, a reader re-encodes the parsed value
and refuses it as `malformed` if the bytes differ.

All 0.5 signed bodies (authority `/5`, requests, links, calls, heads, operation headers) MUST
be canonical. 0.4 and 0.3 bodies inside an upgraded account are verified as their own versions
required.

### 2.2 Other encodings

- **Bytes in JSON** are standard padded base64. Writers emit the canonical spelling; 0.5
  readers refuse any other spelling as `malformed`. `requestId` alone is unpadded base64url
  (§12.2).
- **Embedded envelopes** (a request inside a grant, a link inside a call) are the standard
  padded base64 of the embedded envelope's canonical JSON bytes, exactly as 0.4 embeds a
  request in a grant.
- **Dates** are UTC `YYYY-MM-DDTHH:mm:ssZ` or `YYYY-MM-DDTHH:mm:ss.sssZ`. Comparison uses the
  calendar components, with omitted milliseconds as zero. Other zones and leap seconds are
  `malformed`. A date is the signer's claim; no signature proves time.
- **Digests** are lowercase hex SHA-256 of exact bytes: 64 characters unless a rule says "first
  32".
- **Integers** in fields this document defines are JSON integer tokens from 0 to 2^53−1 unless
  a narrower range is stated.

### 2.3 Strict parsing and closed field sets

- Any JSON object, at any depth, with a duplicate member name is `malformed`. This includes
  `clientData` and operation payloads.
- Every object this document defines has exactly the fields it lists. Optional fields MUST be
  omitted when absent. `null` is allowed only where a field's rule says so. An array this
  document calls non-empty MUST NOT be empty. A field of the wrong type is `malformed`.
- An unknown field, kind, form, role, slot kind, term or value is handled by the pipeline of
  §1: it becomes `newerFormat` only after everything that authenticates and authorizes the
  object has passed.
- Unknown `clientData` members are ignored. Operation payloads, import evidence and module
  values follow their own schemas and MAY contain `null`.

### 2.4 Bounds

| Object | Bound on canonical bytes |
| --- | --- |
| Authority body (`/5`) | 1,048,576 |
| Membership request body | 16,384 |
| Link body | 8,192 |
| Call body, including embedded links | 65,536 |
| `args` of a call | 16,384 |
| Head body | 4,096 |
| `clientData` | 8,192 |

Exceeding a bound is `malformed`. A verifier MUST NOT allocate in proportion to a claimed
length before checking the bound.

## 3. Keys

### 3.1 Key descriptor

```json
{"form":"raw","signing":"<base64>","agreement":"<base64>"}
{"form":"webauthn","signing":"<base64>","rp":"id.luff.works","credential":"<base64>",
 "origins":["android:apk-key-hash:<base64url>","https://id.toolsperson.com"],
 "authorityOrigins":["android:apk-key-hash:<base64url>","https://keys.id.luff.works"]}
```

| Field | Rule |
| --- | --- |
| `form` | `raw` or `webauthn`. |
| `signing` | A valid uncompressed 65-byte P-256 point. |
| `agreement` | `raw` only, optional. A valid 65-byte P-256 point. Required when the key opens a `sealed` slot or part. |
| `rp` | `webauthn` only, required. 1–253 bytes: dot-separated labels of 1–63 lowercase ASCII letters, digits and `-`, no label starting or ending with `-`. |
| `credential` | `webauthn` only, required. 1–1,023 bytes. A lookup hint; it MUST NOT affect verification. |
| `origins` | `webauthn` only, optional. 1–32 distinct strings in strictly ascending byte order. Each is either a **web origin**, `https://` followed by a host that satisfies the `rp` grammar, with nothing after the host; or a **platform origin** of 1–512 printable ASCII bytes (0x21–0x7E) that does not start with `http:` or `https:`, for example `android:apk-key-hash:<base64url>`. |
| `authorityOrigins` | `webauthn` only, optional. 1–32 distinct origins in strictly ascending byte order, each one this descriptor allows under §4.3. When present, this controller's signatures on authority entries and `handover` items are valid only from these origins (§4.3). |

The **key ID** is the first 32 lowercase hex characters of SHA-256 of the `signing` bytes.

### 3.2 What `rp` means

`rp` is the WebAuthn relying-party ID the credential was created for. WebAuthn binds a passkey
to it forever, and every assertion carries SHA-256 of it. It is the only place a domain enters
an account. It is a property of one controller, not of the account: one keyring may hold
passkeys for any number of relying parties. A verifier's own domain, origin or deployment
never enters verification (§4.3).

### 3.3 One key, one principal

A **principal** is one controller (by ID), one member (by ID) or one vault generation. Across
one account's whole history:

1. Within a principal, `signing` and `agreement` MUST be different points.
2. Every P-256 point used for signing or agreement, and every key ID, belongs to exactly one
   principal and one usage. No two principals share a point or a key ID, and no signing point
   equals any agreement point.
3. A principal repeats its own keys only by remaining the same principal: a retained
   controller, or the unchanged current vault.
4. A link's `to.signing` (§12.1) MUST NOT be any principal's point in the history the verifier
   holds, and MUST NOT repeat within one call.

An authority entry that would introduce a collision is `malformed`. This rule is per account:
the same passkey or security key MAY be a controller of any number of accounts, and that is
the ordinary way one person controls a personal and a company account.

### 3.4 Private-key work stays in the host

The core holds no platform private key. Every signature, ECDH and PRF evaluation is
two-phase: `begin_*` returns the exact input, and `finish_*` verifies the result before using
it. The vault seed is an account secret, not a platform key: the core MAY hold it in memory for
a session and MUST NOT persist it. The host persists it only inside slots.

### 3.5 COSE_Key at registration

The credential public key MUST be a definite-length CBOR map with exactly five entries and no
duplicate keys: 1 (kty) = 2; 3 (alg) = −7; −1 (crv) = 1; −2 (x) and −3 (y), each a 32-byte byte
string. Integers and lengths use minimal encoding and nothing follows the map. The key is
`0x04 ‖ x ‖ y` and MUST be a valid point. Anything else is `malformed`. Attestation MAY be
recorded and MUST NOT be required.

## 4. Signatures

### 4.1 Envelope

```json
{"body":"<base64>","signature":"<base64>",
 "assertion":{"authenticatorData":"<base64>","clientData":"<base64>"},
 "cosignatures":[{"signer":"<keyID>","signature":"<base64>","assertion":{}}],
 "handover":[{"signer":"<keyID>","signature":"<base64>","assertion":{}}]}
```

- `assertion` is present if and only if the signer's form is `webauthn`; the same holds inside
  each cosignature and handover item.
- `cosignatures` is absent or non-empty, sorted by `signer`, with signers distinct from each
  other and from the primary signer. Only authority envelopes carry it.
- `handover` appears only on a genesis that names a `predecessor` (§15.1).
- Every attached signature MUST verify. One failing or foreign signature makes the whole
  object `badSignature`.
- Requests, links, heads and operation headers carry exactly `body` and `signature`, signed
  `raw`. A call carries `body`, `signature` and, when signed by a WebAuthn controller,
  `assertion` (§12.2). Any other field on these is `malformed`.

### 4.2 `raw`

`signature` is 64 bytes, `r ‖ s`: ES256, ECDSA P-256 over SHA-256 of the exact body bytes.

### 4.3 `webauthn`

A verifier MUST check, in order:

1. `clientData` parses under §2.3 and contains `type` equal to `"webauthn.get"`, `challenge`
   equal to the unpadded base64url of SHA-256(body), an allowed `origin` (below), and
   `crossOrigin` absent or `false`. Other members are ignored.
2. `authenticatorData` is at least 37 bytes, and bytes 0–31 equal SHA-256 of the UTF-8 `rp`.
3. The flags byte (32) has UP (0x01). UV (0x04) MUST be set when the controller has
   `verification: true`, and for every signature that a rule in this document marks "with UV".
4. The sign counter is ignored.
5. Let `M = authenticatorData ‖ SHA-256(clientData bytes)`. `signature` is exactly
   `0x30 ‖ len ‖ 0x02 ‖ rlen ‖ r ‖ 0x02 ‖ slen ‖ s` and nothing after it; every length is one
   byte below 0x80 and `len = rlen + slen + 4`; `r` and `s` are each 1–33 bytes with the first
   byte at most 0x7F; a leading 0x00 only when the next byte is 0x80 or higher; both decode
   big-endian into [1, n−1]. It is verified as ES256 over SHA-256(M). High-S is valid; a
   library that enforces low-S MUST normalize `s` to `min(s, n−s)` after these checks and
   before verifying. Stored bytes never change.

**Allowed origins.** An origin is allowed when it is a member of `origins`, or when it is
`https://` followed by a host with no port, path, query, fragment or user information (none of
`/ : ? # @ \`), where the host equals `rp` or ends with `.` ‖ `rp` with a non-empty prefix that
does not start or end with `.` and does not contain `..`. **For an authority entry or a
`handover` signature,** if the descriptor has `authorityOrigins`, the origin MUST also be a
member of `authorityOrigins`.

`authorityOrigins` lets an owner say that a passkey may change the account (grant, revoke,
change keys) only from named ceremony origins, while it may still sign calls, such as sign-in,
from any allowed origin. It narrows which scripts can obtain an authority signature from that
passkey. It cannot separate two ceremonies that report the same origin: a native app whose
assertions carry `https://<rp>` and a web page served at `https://<rp>` look the same. A relying
party that wants the separation SHOULD serve no script at the bare `rp` origin and run authority
ceremonies only at a dedicated, minimal origin listed in `authorityOrigins`.

A web origin in `origins` records the owner's consent to WebAuthn Related Origin Requests for
that origin. Browsers enforce the relying party's own related-origins file at ceremony time;
Colophon independently refuses an origin the owner did not list, so a relying party operator
cannot add an origin to someone's account by editing that file.

**Where the verifier is does not matter.** A verifier MUST NOT compare `origin`, `rp` or
anything else with its own origin, host or deployment. The same assertion verifies
identically for every reader, so two releases of the same software (for example production
and staging) reading the same account reach the same result. A service MAY refuse a **call**
(§12) for local reasons, such as requiring UV; it MUST NOT refuse an **authority entry** or a
**head** that this document accepts, because authority validity must agree across readers.

## 5. Accounts and references

### 5.1 The account identifier

An account's **ID** is all 64 lowercase hex characters of SHA-256 of the exact body bytes of
its first authority entry. Its text form, where a string must say what it is, is
`colophon:` followed by the ID.

An account upgraded in place from 0.4 (§16.1) keeps the same first entry, so its 0.5 ID is the
full digest whose first 32 characters are its 0.4 library ID. A 32-character ID is a **legacy
library ID**. It appears only inside 0.4 entries and `/3` operation headers of an upgraded
account; anywhere a 0.5 format names an account, a 32-character value is `malformed`. A legacy
ID found outside an account (for example in an old database row) is resolved only by obtaining
that account's history and checking that the full ID begins with it.

### 5.2 References and hints

```json
{"account":"<64 hex>","hints":["https://home.example/v1/accounts/<64 hex>"]}
```

- `hints` is optional: 1–8 `https://` URLs of at most 512 bytes each. A hint is never signed
  and never part of any digest.
- A hint is untrusted. Whatever it returns is checked against `account` under §8, or dropped.
- A reader that fetches a hint MUST send no cookie, credential, call or account secret; MUST
  bound response size, time and redirects (at most 5); and, when it runs on a server, MUST
  refuse loopback, private, link-local, unique-local and cloud-metadata destinations after every
  DNS resolution and redirect, checking the address it actually connects to. A client that
  lets a user allow a local destination MUST ask, and say that the hint's owner learns of the
  lookup.

## 6. Controllers and the keyring

### 6.1 Controller

```json
{"key":{"form":"webauthn","signing":"…","rp":"id.luff.works","credential":"…"},
 "label":"Passkey","roles":["approve","control"],"verification":true}
```

| Field | Rule |
| --- | --- |
| `key` | A key descriptor (§3.1). |
| `label` | 1–200 bytes. Display only. |
| `roles` | Non-empty, sorted, duplicate-free subset of `approve`, `control`, `recover`. |
| `verification` | `webauthn` only. Present only as `true`: every signature by this controller needs UV. |

The controller ID is its key ID. A controller is always a key: an account is never a controller
of another account in 0.5 (changes §C, "Accounts as controllers").

- `approve`: sign grants, renewals, revocations, session ends and rekeys (the single rule).
- `control`: change the keyring, the layout and the policy (the control and add rules).
- `recover`: add keys when others are lost (the recovery rule).

### 6.2 Keyring

```json
{"controllers":[…],"threshold":1,"recoverThreshold":1,"addThreshold":1,
 "policy":{"callWindow":300,"headMaxAge":300,"headQuorum":1,"history":"members","linkMaxAge":86400},
 "vault":{"signing":"…","agreement":"…"},"slots":[…]}
```

| Field | Rule |
| --- | --- |
| `controllers` | 1–64, sorted by ID, no duplicates. At least one holds `control`. |
| `threshold` | Integer from 1 to the number of `control` controllers. Signers needed for the control rule. |
| `recoverThreshold` | Integer, always present. 0 if no controller holds `recover`; otherwise 1 to the number of `recover` controllers. It MAY exceed `threshold`. |
| `addThreshold` | Integer from 1 to `threshold`. Signers needed for the add rule (§8.4). |
| `policy` | The account's policy object (§6.3). |
| `vault` | The vault's public identity (§7.1). |
| `slots` | 1–256 slots, each valid under §7.2. |

### 6.3 Policy

`policy` has exactly these fields. They bind every verifier of this account; a verifier MAY be
stricter in what it accepts for calls, never more lenient.

| Field | Meaning | Range |
| --- | --- | --- |
| `headMaxAge` | Seconds a head stays fresh (§13.3) | 30–86,400 |
| `headQuorum` | Distinct homes whose fresh heads a call verifier needs (§13.3) | 1–8 |
| `callWindow` | Seconds a call's `created` may differ from the verifier's clock (§12.3) | 30–3,600 |
| `linkMaxAge` | Most seconds from a link's `notBefore` to its `expires` (§12.1) | 60–2,592,000 |
| `history` | Who a home serves the history to: `members` or `public` (§13.4) | — |

Defaults, and who may change each field, are in §18.

### 6.4 Warnings

Hosts SHOULD warn, in words, whenever losing any one key would leave no control quorum, no
recovery quorum where the person chose to have one, or no openable slot; when fewer recovery
controllers exist than the person's chosen number; and when no recovery controller has a slot.

## 7. Vault and slots

### 7.1 Vault

The vault seed is 32 random bytes from the host. Its identity is
`s' = HKDF-SHA256(IKM = seed, salt = "colophon/vault/4", info = "identity", 32 bytes)`, then the
software-identity procedure of §7.4 on `s'`. The `/4` in these and the slot labels below is a
domain-separation label, not a version marker, and is unchanged in 0.5.

**Each newly introduced epoch MUST be sealed to exactly the current vault and the active,
unexpired members with any access to its namespace (§10.2), at the introducing entry.**
Historical seals stay valid authenticated history. Later `shares` add only the recipients this
document authorizes.

After opening any slot, the core MUST check the plaintext is 32 bytes, derive the identity and
compare both public keys with the keyring's `vault`. A mismatch is `refused:vaultLocked` and
leaves the session's seed unchanged.

### 7.2 Slots

Every slot has exactly `kind`, `controllers` (IDs of current controllers), `label` (1–200
bytes) and its kind's fields:

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

`vaultID` is the key ID of the vault's signing key. Part indices are zero-based; part secrets
are exactly 32 bytes and concatenate as `S0 ‖ … ‖ S(n−1)`.

| Kind | Shape | Opening |
| --- | --- | --- |
| `sealed` | One `raw` controller with `agreement`. `sealed` is `{enc (65-byte point), ciphertext (48 bytes)}`. | HPKE (§11.1 suite) to that agreement key, `info` and AAD `I`. The plaintext is the seed. |
| `prf` | One `webauthn` controller. `salt` 32 bytes, `box` 60 bytes. | PRF output `P`. Key = HKDF-SHA256(IKM `P`, salt `salt`, info `I`, 32 bytes). `box` = nonce(12) ‖ AES-256-GCM(seed, AAD `I`) ‖ tag. |
| `combined` | At least 2 distinct controllers; `parts` has the same length and order; `box` 60 bytes. Part `i` is `{"kind":"sealed","sealed":…}` for a `raw` controller with `agreement`, or `{"kind":"prf","salt":…}` for a `webauthn` controller. | Sealed part: HPKE with `info` and AAD `Ii`. PRF part: HKDF(IKM `P`, salt, info `Ii`). Key = HKDF-SHA256(IKM `S0 ‖ … ‖ Sn−1`, salt empty, info `I`, 32 bytes); then `box` as for `prf`. |

Each sealed part MUST encrypt a fresh independent random 32-byte secret, never the seed and
never reused. A wrong secret is `refused:vaultLocked`. Structural violations are `malformed` at
replay, not when the slot is first opened.

**PRF bytes.** `salt` is the exact WebAuthn PRF input (`prf.eval.first`); `P` is the 32-byte
`results.first`. A host that talks CTAP `hmac-secret` directly MUST apply
SHA-256(`"WebAuthn PRF"` ‖ 0x00 ‖ salt) and select the UV-associated secret. Missing PRF MUST
fail explicitly; there is no fallback derivation.

**Building a PRF route.** A PRF output used to build a `prf` slot or part MUST come from an
assertion (`get`) restricted to that slot's credential, evaluating the slot's salt and signing a
fresh random 32-byte challenge from the core (never a body digest). Registration-time PRF
outputs MUST NOT be used. The core MUST verify that assertion against the new controller's key
before building the slot, and MUST open the built slot with the same output and check the vault
(§7.1) before the slot is published. The host is trusted to pass PRF bytes unchanged from the
platform for the exact pending request, credential and salt.

### 7.3 Moving the seed to a new device

To add a controller whose ceremony happens on a device that does not hold the seed (a passkey
on a new platform, §17.3), the device holding the seed MAY transfer it:

- The new device generates an ephemeral P-256 agreement key `E` for this transfer only, and
  both devices display the pairing code of §9.1 computed over `E`'s public point.
- After a person confirms the codes match, the seed holder seals the seed with HPKE (§11.1
  suite) to `E`, with `info` and AAD
  `"colophon/vault-transfer/5\n" ‖ accountID ‖ "\n" ‖ keyID(E)`.
- The new device opens it, checks the vault (§7.1), builds the slot and erases the seed and
  `E` when the session ends.

The transfer gives the new device what its slot will give it anyway. It MUST NOT be offered to
a device that is not about to become a controller with a slot.

### 7.4 Software identities and kits

A software identity is expanded from a 32-byte seed with HKDF-SHA256, salt
`colophon/entropy/3`, info the eight-byte big-endian counter from zero, 32 bytes: the first
valid scalar signs, the next valid scalar agrees, and invalid scalars consume a counter. A
recovery kit is a software identity whose seed is 32 secret bytes printed or stored by the host;
it is a `raw` controller with `agreement`, usually `recover` only.

## 8. Authority history

### 8.1 Body

Every authority body contains `protocol`, `seq` (contiguous from 1), `previous` (SHA-256 hex of
the exact preceding body, `null` only at seq 1), `issued`, `by` (the primary signer's ID), `kind`
and that kind's fields. New accounts use `protocol: "colophon/authority/5"` from seq 1. An
account upgraded from 0.4 has `colophon/authority/4` entries up to and including its `upgrade`
entry and `/5` after it (§16.1). Any other mixture is `malformed`.

The history is a single chain. Two different valid entries with the same `seq` are a fork: a
replica keeps the first it accepted, keeps the other as evidence, and the host shows it.
Writers publish each entry and await acknowledgement before its successor (0.3 §8).

### 8.2 Kinds

| Kind | Fields | Effect |
| --- | --- | --- |
| `genesis` | `label` (1–200 bytes), `namespaces`, `keyring`, optional `predecessor` (§15.1) | Creates the account and its first keyring. The vault MUST be fresh. |
| `rekey` | `epochs` (non-empty) | Introduces consecutive epochs (§11.1). **If the account declares namespaces, seq 2 MUST be a `rekey` introducing epoch 1 for exactly the declared namespaces.** An account with no namespaces has no epochs and no such rule. |
| `grant` | `request`, `terms`, `shares` | Admits a new member (§9). |
| `renew` | `member`, `expires`, `shares` | Changes a member's expiry (§9.4). |
| `revoke` | `member`, `kept`, `heads`, `epochs` | Ends a member (§9.5). |
| `endSessions` | `member` | Ends every link under a member (§9.6). |
| `keyring` | `keyring`, and `shares` plus `epochs` only if the vault changes | Replaces the keyring wholesale (§8.3). |
| `layout` | `layout` | Raises the storage layout. It never lowers it. |
| `successor` | `account` (64 hex, not this account) | States that the account's owner continues in another account (§15.2). Confers nothing. |

`namespaces` is 0–64 distinct names: lowercase ASCII letters, digits, `.` and `_`, at most 128
bytes, sorted. `layout` is an integer; 0.5 defines layout 2 (0.3 §4).

### 8.3 Keyring transitions

**When the vault is unchanged, every existing slot MUST stay,** compared as a multiset by
canonical JSON of the slot without `label`. Slot order and labels MAY change and slots MAY be
added. `shares` and `epochs` MUST then be absent.

**When the vault changes,** the new vault MUST be fresh (§3.3), `shares` MUST seal every
existing epoch to the new vault, and `epochs` MUST introduce a new epoch in every namespace.

**Rotation is required** when any of these happens to a controller present before the entry:
it is absent afterwards; it loses any role; its `agreement` changes or is removed; or any
existing slot is deleted or its cryptographic fields change. Changing only `label`,
`verification`, `credential`, `origins`, `authorityOrigins`, `addThreshold`, the thresholds or
`policy` does not require rotation; each is still a control-rule change. A properly signed
entry that omits a required rotation is `malformed`.

### 8.4 Who may sign what

Signers of every entry except `genesis` are evaluated against the keyring and member table
**before** the entry. Genesis signers are evaluated against the genesis keyring.

| Kind | Rule |
| --- | --- |
| `genesis` | Control rule over the new keyring; and the predecessor rule if `predecessor` is present (§15.1). |
| `keyring` | Control rule. If it fails, the add rule. If that fails, the recovery rule. If all fail, `badSignature`. |
| `layout`, `successor` | Control rule. |
| `grant`, `renew` | Control rule when the member's terms (granted or existing) contain `import` or `serves`; otherwise the single rule. |
| `rekey`, `revoke` | Single rule. For `rekey`, holding `control` instead of `approve` is also enough. |
| `endSessions` | Single rule, or the member rule. |
| `upgrade` (`/4`) | 0.4 control rule (§16.1). |
| unknown kind | Control rule. |

- **Control rule.** Every signer holds `control`, the number of distinct signers is at least
  `threshold`, and every WebAuthn signature has UV.
- **Add rule.** Every signer holds `control`; the number of distinct signers is at least
  `addThreshold`; every WebAuthn signature has UV; the change **only adds** (below); and every
  added controller's roles respect the add limits: `control` only if `addThreshold` equals
  `threshold`; `recover` only if `recoverThreshold` ≥ 1 and `addThreshold` ≥ `recoverThreshold`;
  `approve` always.
- **Recovery rule.** `recoverThreshold > 0`; every signer holds `recover`; the number of distinct
  signers is at least `recoverThreshold`; every WebAuthn signature has UV; the change only adds;
  and **if `recoverThreshold < threshold`, every added controller has roles exactly
  `["approve"]`.**
- **Only adds.** Every existing controller is identical by canonical JSON of the whole
  controller; `threshold`, `recoverThreshold`, `addThreshold`, `policy` and `vault` are
  unchanged; every existing slot is preserved as a multiset by canonical JSON including its
  label; and only new controllers, and slots naming only new controllers, are added.
- **Single rule.** Exactly one signer, no cosignatures, holding `approve`.
- **Member rule.** `endSessions` only: `by` equals `member`, the signer is that current member,
  signing `raw` with its member key, with no cosignatures. A member can end its own sessions and
  nothing else.

### 8.5 Verification order

For seq > 1 the verifier MUST, in this order:

1. Parse the envelope and body as generic JSON (duplicate names refused) within §2.4's bound.
   Check the header: `protocol` (as §8.1 allows at this position), `seq` (the next number),
   `previous` (the last digest) and `issued`; any failure is `malformed`. `by` MUST name a
   controller of the prior keyring (or, for `endSessions`, a current member); otherwise
   `badSignature`, as the 0.4 engine reports it.
2. Verify every attached signature against the prior keyring or member table (§4). Any failure
   is `badSignature`.
3. Decide the rule: a known kind uses §8.4; an unknown kind uses the control rule. If the rule
   is not met, the result is `badSignature`.
4. Only now look for unknown content anywhere in the body: an unknown kind, field, form, role,
   slot kind, part kind, term, policy field or value. If any is found, the result is
   `newerFormat`.
5. Apply the full typed schema, §2.4's bounds and the transition rules of §8.2, §8.3, §9, §15
   and §16. A violation is `malformed`.

For genesis, the same order applies with the genesis keyring, and unknown values in its own
keyring are `newerFormat` once its control rule (and any predecessor rule) is met. A forged
genesis can't enter an existing account, because the account ID is the genesis digest.

A verifier MUST NOT be stricter or more lenient than this section for authority entries. Every
reader of an account must reach the same history.

## 9. Members

### 9.1 Membership request

A key asks to join by signing, `raw`, a request:

```json
{"protocol":"colophon/request/5","account":"<64 hex>",
 "member":{"signing":"<base64>","agreement":"<base64>"},
 "label":"Codex on optiplex","kind":"agent","terms":{…},"created":"2026-11-11T09:00:00Z",
 "service":{"endpoints":["https://home.example/v1/accounts/<64 hex>"]}}
```

| Field | Rule |
| --- | --- |
| `member` | A public identity: two distinct valid P-256 points. The member ID is the key ID of `signing`. |
| `label` | 1–200 bytes. |
| `kind` | `device`, `app`, `agent` or `server`. Signed attribution: records by an `agent` member are shown as written by AI (0.3 §6 `origin`). |
| `terms` | The terms asked for (§10). MUST NOT contain `import`. |
| `service` | Present if and only if `terms.serves` is present. `endpoints` is 1–8 distinct `https://` URLs of at most 512 bytes, sorted. Endpoints are discovery data: they never create authority without the grant. |

A request is stored at `requests/<memberID>.json` and is immutable. Both sides display the
**pairing code**: the first four bytes of SHA-256(UTF-8 account ID ‖ signing-key bytes),
big-endian, modulo 1,000,000, as six decimal digits. Hosts show it before approval.

### 9.2 Grant

A `grant` entry admits the requesting key. Its `request` is the embedded request envelope
(§2.2), which MUST verify under its own `member.signing` key and name this account. Its `terms`
are what is granted, and MUST be **covered by** the requested terms:

- every `records` entry of the grant matches a requested entry for the same namespace with
  equal or higher access, and, if the requested entry has `kinds`, the granted entry has `kinds`
  that are a subset;
- every `services` entry matches a requested entry for the same audience whose purposes are
  `["*"]` or a superset;
- `serves` is a subset of the requested `serves`;
- `import` may be added only by the approvers (§9.3); `expires`, `writes`, `depth` and
  `conditions` are set by the approvers.

Further rules:

- The member ID MUST NOT be a current or former member, controller or vault key ID of this
  account (§3.3). One key is admitted once.
- Every granted `records` namespace MUST be declared.
- `shares` seals every historical epoch of every namespace in `records` to the member's
  agreement key; it is empty when `records` is absent.
- `serves` MUST NOT be granted to a member of kind `agent`.

### 9.3 Import

`terms.import` (present only as `true`) lets the member publish `colophon.importBatch` (0.3
§7.2) in its granted namespaces. In 0.5, every 0.3 rule that names the root's import role
names this term instead. An import grant MUST: give `write` in every `records` entry; have
`expires` later than the entry's `issued`; be signed under the control rule; and be for a
member whose request `kind` is `device` or `app`. Readers compare a parent operation's signed
`created` with `expires` and MUST NOT use first-seen time as an admission rule. To stop further
imports, revoke the member.

### 9.4 Renew

`renew` sets `member`'s expiry to `expires`, which MUST be later than the entry's `issued`. The
member MUST be current (not revoked). `shares` seals to the member every epoch in its `records`
scope it lacks a seal for, including epochs introduced while it was expired (possibly none). A
renewal never changes any other term; a different scope needs a new member key and a new grant.

### 9.5 Revoke

`revoke` ends `member`. `epochs` introduces a new epoch in every namespace the member could
read (empty if none). Records the member wrote are kept only when the entry names them:

- `kept` is the sorted, distinct list of digests of exact signed operation header bodies by the
  member that remain admitted. It is used for `/3` operations and for live-stamped operations
  (§11.2), which are not on author chains. It may be empty.
- `heads` is a list, sorted by namespace, of at most one `{"namespace":…,"digest":…}` per
  namespace: the digest of the last header body the approver accepts on the member's author
  chain in that namespace (§11.2). It may be empty.

A record by the revoked member is **kept** exactly when its header-body digest is in `kept`, or
equals a `heads` digest, or is reachable from a `heads` digest by following `previous` links
through headers of the same author and namespace. Everything else by that member after
revocation is handled by §11.5 step 3. Kept records still pass every other admission check.

The approver's host computes `kept` and `heads` from every record it holds; records it has not
seen are not kept. This is the same exposure as 0.4 and cannot be avoided without an orderer.

### 9.6 Ending sessions

Each member has a **session number**, 0 when admitted. `endSessions` adds 1 to `member`'s
session number. Every link made under an earlier number stops passing §12.4 at any verifier
holding this entry. It doesn't take back anything a session already did or read.

### 9.7 What a member is never

A member is never a controller (§3.3). Its key never signs an authority entry except its own
`endSessions`. No term, kind or policy makes a member a controller in 0.5.

## 10. Terms

### 10.1 Fields

Terms are one JSON object:

```json
{"records":[{"namespace":"notes","access":"propose","kinds":["addNote"]}],
 "services":[{"audience":"https://projects.luff.works/scopes/7","purposes":["task.read","task.propose"]}],
 "expires":"2026-11-18T09:00:00Z","writes":500,"depth":1,
 "conditions":[{"lte":["args.amount",5000]}],"serves":["home"],"import":true}
```

| Field | Rule |
| --- | --- |
| `records` | 1–64 entries with distinct namespaces. `access` is `read`, `propose` or `write`; `write` includes `propose` and `read`; `propose` includes `read`. `kinds`, optional, is 1–64 distinct operation kinds (1–128 bytes of `A–Z a–z 0–9 . _ -`) and limits what the member may propose or write. |
| `services` | 1–64 entries with distinct audiences. `audience` names a system outside the account: an `https://` URL (host by the `rp` grammar, optional path, no port, query, fragment or user information) or a `urn:` URI, 1–512 printable ASCII bytes. `purposes` is `["*"]` (every purpose at that audience) or 1–64 distinct purposes, each 1–128 bytes of `A–Z a–z 0–9 . _ : / -`. |
| `expires` | The last moment the terms hold, inclusive. Absent: no expiry. |
| `writes` | Most admitted records under these terms, counted as 0.3 §5 counts `writeBudget`. Absent: no limit. Zero permits no writes. |
| `depth` | 0–4: how many links may follow (§12.1). Absent means 0. |
| `conditions` | 1–32 predicates that must all hold (§10.4). |
| `serves` | `["home"]`. It makes the member a home (§13.1). |
| `import` | `true` (§9.3). |

Terms MUST contain at least one of `records`, `services` or `serves`. Link terms (§12.1) MAY
contain only `services`, `depth` and `conditions`, and MUST contain `services`.

**Granting to a system.** A `services` entry is how an account grants a key permission at a
system it does not hold: a Galley instance, a staging release, an identity service. The system
defines its purposes; Colophon checks that a call's audience and purpose are granted. Two
releases of one service are two audiences, so a grant to production does not reach staging
unless it names staging too. Nothing about the account or its data changes between them.

### 10.2 Access to records and sealing

A member with any `records` entry for a namespace receives that namespace's epochs: proposing
and writing require the namespace key to seal a record, and possession of a key inherently
enables reading. Proposing into a namespace a key cannot read is not part of 0.5.

### 10.3 Narrowing

Link terms B **narrow** parent terms A (the member's terms, or the previous link's) when:

- every `services` entry of B has an entry in A with the same audience, and A's purposes are
  `["*"]` or contain every purpose of B (B's `["*"]` requires A's `["*"]`);
- B's `depth` (absent 0) is less than A's;
- every predicate of A's `conditions` is equal, by canonical JSON, to some predicate of B's.

There is no other inheritance: a link's lifetime is narrowed by its own `expires` (§12.1).

### 10.4 Conditions

A predicate is one of `{"eq":[path,value]}`, `{"in":[path,[values]]}` (1–64 values),
`{"prefix":[path,string]}`, `{"lte":[path,number]}`, `{"gte":[path,number]}`,
`{"all":[predicates]}`, `{"any":[predicates]}` or `{"not":predicate}`.

- **What it reads.** For a call, the call's `args`; for a record, the decrypted `payload`
  (§11.3). A path is a dotted list of object member names, 1–8 segments of 1–64 bytes; a leading
  `args.` segment is ignored. There is no array indexing. A missing path makes `eq`, `in`,
  `prefix`, `lte` and `gte` false.
- **Comparison.** `eq` and `in` compare canonical JSON bytes. `prefix` holds when both are
  strings and the value's bytes start with the literal's. `lte` and `gte` hold only when both are
  numbers: integer tokens compare exactly as integers, binary64 values by IEEE-754, and an
  integer against a binary64 exactly, without converting the integer to binary64.
- **Logic.** Empty `all` is true and empty `any` is false. `not` inverts, including a false from
  a missing path; write `all` with a presence test when absence must fail.
- **Bounds.** At most 32 predicates in all (each `all`, `any` and `not` counts), nested at most 4
  deep (the outermost is depth 1), and at most 4,096 bytes of canonical JSON for the whole
  `conditions` array. Beyond these is `malformed`. There are no loops, functions or code.

Whoever makes the final decision MUST see the plaintext and evaluate every applicable
predicate: a decrypting reader for records, the audience for calls. A server that holds only
ciphertext never claims a condition passed.

## 11. Records

### 11.1 Namespace encryption

Each declared namespace has consecutive epochs from 1, each a fresh 256-bit AES key. An epoch
is `{"namespace","epoch","seals":{recipientID: sealedKey}}`, and a sealed key is
`{"enc","ciphertext"}` under RFC 9180 base mode with KEM 0x0010 (DHKEM(P-256, HKDF-SHA256)),
KDF 0x0001 (HKDF-SHA256) and AEAD 0x0002 (AES-256-GCM), one message at sequence zero. HPKE
`info` and AAD are both
`colophon/epoch/3\n<libraryID>\n<namespace>\n<epoch>\n<recipientID>`, where `<libraryID>` is
the first 32 characters of the account ID. This label is unchanged from 0.3, so epochs of an
upgraded account keep opening. Decapsulation takes raw 32-byte ECDH from the host and does the
key schedule in the core. Hosts supply a fresh random 32-byte seed per action; the core
expands it with §7.4's procedure for epoch keys, ephemeral scalars and nonces.

### 11.2 Operation header

An operation is stored at `ops/<author>/<namespace>/<clock, 12 digits>-<id>.json` and its
signed header body is:

```json
{"protocol":"colophon/operation/5","account":"<64 hex>","namespace":"notes","author":"<memberID>",
 "epoch":1,"id":"<32 hex>","clock":7,"authority":12,"created":"2026-11-11T12:00:00Z",
 "level":"write","previous":"<64 hex or null>","nonce":"<base64, 12 bytes>","ciphertext":"<base64>"}
```

- It is signed `raw` by the author's member key. `author` and `namespace` MUST match the path.
- `level` is `write` or `propose`.
- `previous` is the digest of this author's preceding operation header body in this namespace
  (its **author chain**), or `null` for its first. A writer MUST persist its chain head before
  publishing and MUST rebuild it from the records it holds after any restore. A chain fork (two
  headers naming the same `previous`) is author misbehaviour: both remain admissible, and
  revocation keeps only the branch the approver names (§9.5). Admission never waits for a
  missing predecessor.
- An optional signed `live` stamp `{"account","slot","generation","operationID"}` marks
  replaceable playback state (0.3 §5.1 with §11.8's substitutions). A live-stamped header MUST
  have `level` `write` and `previous` `null`; it is not on an author chain.
- **AAD** for the payload is the canonical JSON of the header without `nonce`, `ciphertext` and
  `live`: `{account, author, authority, clock, created, epoch, id, level, namespace, previous,
  protocol}`. `nonce` is 12 bytes; `ciphertext` includes the 16-byte tag.

### 11.3 Plaintext and operation ID

The plaintext is `{"id","kind","v","clock","authority","created","payload"}` exactly as 0.3 §5.
The operation ID is the first 32 hex characters of SHA-256 of canonical JSON of
`{"purpose":"colophon/operation-id/3","namespace","author","epoch","nonce","operation"}`, where
`nonce` is an array of twelve integer octets and `operation` is the complete plaintext with
`id:""`. Plaintext ID, clock, authority and date MUST match the header, and the ID MUST verify
after opening.

### 11.4 Fold order and clocks

Fold order is `(clock, author, id)`, never `created`, and the clock rules of 0.3 §5 apply
unchanged: positive integers at most 2^53−1, increment past the highest admitted clock in the
namespace, and a jump of more than 1,024 over the highest earlier admitted clock is refused as
`clockJump`.

### 11.5 Admission

After validating the header's signature, account binding, format and path, a reader admits it
in this order:

1. The author is a member with a `records` entry for the namespace whose access covers
   `level`, at the verified authority (the latest verified for a future claim): else refused
   `notGranted`.
2. `created` is later than the member's expiry in the latest verified authority: refused
   `expired`.
3. The author is revoked and the record is not kept (§9.5): refused `revoked` if it cites the
   revocation or later; otherwise held `revokedBackdated`.
4. `authority` is newer than this replica: held `authorityBehind`.
5. The epoch was not current at that sequence: refused `wrongEpoch`.
6. The clock exceeds the forward-jump bound: refused `clockJump`.
7. Earlier admitted headers have spent `writes`: refused `budgetSpent`.
8. Otherwise the header is admitted and reserves one budget slot per distinct `(author, id)`.

After opening the payload: if the entry has `kinds` and the plaintext `kind` is not in it, or a
`conditions` predicate fails on `payload`, the record is refused `outOfScope` in the view's
refused list and still reserves its budget slot (as 0.3 does for `invalidPayload`). A reader
missing an epoch key holds the content as `unavailable`. Every other rule of 0.3 §5 for
`invalidPayload`, `duplicateID` and unknown payload versions applies.

**In an upgraded account,** a `/3` header is admitted under 0.3 §5 and 0.4 rules only if it
cites an authority sequence before the `upgrade` entry and its `library` equals the account's
legacy ID; a `/5` header MUST cite the `upgrade` sequence or later. Anything else is refused
`wrongFormat`.

### 11.6 Proposals

A `propose` record is admitted like a write but is **not folded** as one. It is a proposal,
identified by its operation ID.

- `colophon.accept` and `colophon.decline` are core kinds with payload
  `{"proposals":["<operation ID>", …]}` (1–64 distinct IDs). Each is a `write` record in the
  proposals' namespace. It resolves a proposal only if its author's terms allow `write` for the
  proposal's kind (checked after decrypting both).
- For each proposal, the **first** valid resolution in fold order wins. Later resolutions
  remain evidence and change nothing.
- An accepted proposal is folded exactly once, at its accept record's position in fold order,
  attributed to its proposer with `acceptedBy` set to the accepter. It counts once against the
  proposer's `writes` (as the proposal it already is) and the accept record once against the
  accepter's.
- A resolution naming a proposal the reader doesn't hold is held as `unavailable` for that
  proposal; when it arrives, the order is still decided by the resolution's position.
- Views list unresolved and declined proposals separately from state. Any irreversible effect
  outside the account MUST NOT be taken on the strength of an acceptance a reader could later
  see reordered by an earlier-sorting resolution.

### 11.7 Basis

`basis` is a reserved payload field: a list of `{"claim":"<word>","ref":"<record id or URL>"}`
objects with an optional `"digest":"<64 hex>"`, at most 32. The core checks only its shape;
modules define what claim words mean. Attempted, tested, built, delivered and accepted are
different claims.

### 11.8 Incorporated 0.3 mechanics

0.3 §5.1 (live state and engagement evidence), §6 (modules, views, tools and the ledger), §7
(host contract, verified-prefix cache, import and blobs) and §8 (HTTP relay) are normative for
0.5 with these substitutions: "library" reads "account"; `libraryID` in a live stamp reads
`account` with the 64-hex ID; "root-only" and "root role" read "the `import` term" (§9.3);
"member kind" reads the request `kind` (§9.1); a grant's namespaces and access read its
`records` entries; `writeBudget` reads `writes`; and `/3` header rules read §11.2–§11.5 for
`/5` headers. Where 0.3 names the layout-2 storage paths, they are unchanged; 0.5 adds none.
Where 0.3 says one access set applies to all of a grant's namespaces, 0.5 applies each entry's
own access.

## 12. Links and calls

### 12.1 Link

A link passes part of a member's grant to a short-lived key:

```json
{"protocol":"colophon/link/5","account":"<64 hex>","from":"<keyID>",
 "to":{"signing":"<base64>"},"session":3,
 "terms":{"services":[{"audience":"https://projects.luff.works","purposes":["task.read"]}]},
 "notBefore":"2026-11-11T09:00:00Z","expires":"2026-11-11T09:10:00Z","created":"2026-11-11T09:00:00Z"}
```

- It is signed `raw` by `from`'s key. The first link of a chain is from the member; each later
  link is from the previous link's `to` key.
- `session` is present on the first link only, as the member's session number when it was made.
- `notBefore` ≤ `expires`, and `expires` − `notBefore` is at most `policy.linkMaxAge`.
- `terms` are link terms (§10.1).

### 12.2 Call

A key acts for an account at a system by signing a call:

```json
{"protocol":"colophon/call/5","account":"<64 hex>","asOf":{"seq":41,"digest":"<64 hex>"},
 "signer":{"member":"<memberID>"},"key":"<base64 signing point>","links":["<base64>"],
 "audience":"https://projects.luff.works","purpose":"task.read","args":{"task":"T-12"},
 "requestId":"<43 chars>","created":"2026-11-11T09:01:00Z"}
```

| Field | Rule |
| --- | --- |
| `asOf` | An authority entry the signer had seen: its `seq` and body digest. |
| `signer` | Exactly one of `{"member":"<id>"}` or `{"controller":"<id>"}`. |
| `key` | The acting key's 65-byte signing point. |
| `links` | 1–8 embedded link envelopes, in order from the member outward. Absent when the member's own key acts, and always absent for a controller. |
| `audience` | The system being asked, in the `services` audience grammar (§10.1). |
| `purpose` | The system's purpose name (§10.1 grammar). `colophon.` purposes are reserved for §13–§14. |
| `args` | A JSON object, at most 16,384 bytes. Large inputs are named by digest. |
| `requestId` | 32 random bytes as unpadded base64url (43 characters). |

The envelope is `{"body","signature"}` signed `raw` by `key`, or, when `signer` is a `webauthn`
controller, `{"body","signature","assertion"}` signed as §4.3.

### 12.3 Verifying a call

A verifier MUST, in order:

1. **Parse.** Bounded generic parse of the envelope, the body and every embedded link (§2.3,
   §2.4); `protocol`s known; `account` a 64-hex ID; `signer` and `key` well formed.
   Otherwise `malformed`.
2. **Possession.** Verify the envelope's signature under `key`: ES256 over the body for `raw`;
   for an assertion, `clientData` `type`, `challenge` and `crossOrigin` and the ECDSA check of
   §4.3 step 5 under `key`. Otherwise `badSignature`. Nothing is fetched before this step.
3. **Audience, time, replay.** `audience` is one of the verifier's own audiences, else
   `refused:audience`. `created` is within the verifier's window of its clock (at most
   `policy.callWindow` once known), else `refused:window`. If this verifier recorded the same
   `requestId` for this account and audience: identical body bytes return the recorded result
   and perform no new effect; different bytes are `refused:conflict`.
4. **History.** The verifier holds a verified history containing `asOf.seq` with that digest
   (a different digest there is `refused:fork`), and fresh heads from at least
   `policy.headQuorum` distinct current homes (§13.3), and its history reaches the highest of
   those heads. It fetches what it lacks; if it can't, `unavailable`. Now that the account's
   policy is known, `created` MUST also be within `policy.callWindow` of the verifier's clock,
   else `refused:window`.
5. **Signer.**
   - A controller: present in the latest held keyring, else `refused:revoked`; its descriptor's
     `signing` equals `key` and the assertion passes all of §4.3 with that descriptor, else
     `badSignature`.
   - A member: present, not revoked, else `refused:revoked`; not expired at the verifier's
     clock (inclusive), else `refused:expired`.
6. **Chain.** For each link in order: its signature verifies under the previous key (the
   member's signing key first), else `badSignature`; `account` matches and `from` is the
   previous key's ID, else `badSignature`; the first link's `session` equals the member's
   current session number, else `refused:ended`; `notBefore` ≤ now ≤ `expires`, `expires` no
   later than the previous link's and the member's expiry, else `refused:expired`; its terms
   narrow the previous terms (§10.3), else `refused:notNarrower`. Finally the acting `key`
   equals the last link's `to.signing`, or with no links the member's signing key, else
   `badSignature`.
7. **Purpose.** For a member, the member's terms and every link's terms each have a `services`
   entry for `audience` that allows `purpose`, and every applicable `conditions` predicate holds
   on `args`; otherwise `refused:outOfScope`. For a controller, the verifier decides from the
   controller's roles which purposes it accepts, and refuses others as `refused:outOfScope`.
8. **Extensions.** Only now, an unknown field, term or value anywhere in the authenticated call,
   links or terms is `newerFormat`.
9. Otherwise `ok`.

A copied call fails step 3 or 6 for any other key; a copied link authorizes nothing without a
call signed by its `to` key.

### 12.4 What a call means, and what a verifier keeps

- `ok` means: as of the verifier's fresh heads, this key could act for the account at this
  audience for this purpose with these arguments. It is not a record in the account.
- A verifier MUST record every call that passes step 2 with its result, keyed by account,
  audience and `requestId`, for at least twice `policy.callWindow`, and MUST NOT perform an
  effect twice for one `requestId`.
- A service that acts on a call and writes records does so under its own member key, with a
  `basis` naming the call by digest. Sessions never author records.

## 13. Homes and heads

### 13.1 Homes

A home is a member whose terms contain `serves: ["home"]`, appointed by a `grant` under the
control rule with the endpoints its request names (§9.1). It keeps the account's authority
history exactly as signed, verifies every entry under §8 before storing it, and never stores an
entry that does not extend its history. It may also keep records. An account MAY appoint up to
8 homes and replace any by grant and revoke. A home holds no private key of a controller or
member, no PRF output and no seed.

A genesis may be followed, in one upload, by the entries that appoint a home; a home verifies
the whole batch and stores it only if its own appointment is in it.

### 13.2 Head

```json
{"protocol":"colophon/head/5","account":"<64 hex>","authority":{"seq":41,"digest":"<64 hex>"},
 "issued":"2026-11-11T09:00:00Z","by":"<home member ID>"}
```

It is signed `raw` by the home's member key. It says only: this home held exactly this
verified history up to `seq` at `issued`. It doesn't prove there is no newer entry elsewhere,
and it doesn't prove the history valid: the reader verifies the entries itself.

### 13.3 Verifying and keeping heads

A verifier accepts a head when: it parses within bounds; `by` is a current, unexpired member
with `serves` in the verifier's latest held history, whose key verifies the signature (else
`badSignature`); `issued` is no more than 60 seconds ahead of the verifier's clock; and the
verifier's history, extended by fetching if needed, contains `authority.seq` with that digest
(a different digest is `refused:fork`; failure to fetch is `unavailable`). A head is **fresh**
while `now − issued ≤ policy.headMaxAge`.

- **High-water mark.** A verifier persists, per account, its highest accepted
  `(seq, digest)` and never accepts a history that does not extend it, even with a freshly
  `issued` head. Rollback is refused as `refused:rollback`.
- **Equivocation.** Two heads by one home with the same `seq` and different digests prove that
  home misbehaved. A verifier that holds both MUST keep both, MUST stop counting that home for
  this account, and SHOULD tell the account's controllers.
- **Quorum.** Where a fresh view is needed (§12.3 step 4), heads from `policy.headQuorum`
  distinct homes are compared: one whose `seq` is lower is behind, not wrong; two whose
  histories diverge are a fork (`refused:fork`).
- A home SHOULD sign a new head at least every `policy.headMaxAge` / 2, and MUST NOT sign a head
  for an entry it hasn't verified.

### 13.4 Who may read the history

If `policy.history` is `public`, a home serves the history to anyone. If it is `members`, a home
serves it to callers presenting a valid call (§12.3) with audience equal to one of the home's
endpoints and purpose `colophon.history.read`, signed by a controller, by any current member, or
under terms granting that purpose at that audience. The head is always public. History is
verifiable with public keys only; it is not encrypted, and it names labels, namespaces and
members, which is why it is not public by default.

## 14. Exchange

The HTTP relay of 0.3 §8 is unchanged, with these additions at a home's endpoint `{base}`:

| Request | Response |
| --- | --- |
| `GET {base}/head` | 200 with the home's latest head envelope; 404 if it holds no history. Public, `Cache-Control: no-store`. |
| `GET {base}/authority?after={seq}` | 200 `{"entries":["<base64 envelope>", …],"more":bool}` in order from `after + 1`, subject to §13.4. |
| `POST {base}/authority` | Body `{"from":<seq>,"entries":["<base64 envelope>", …]}`, 1–64 contiguous entries. The home verifies the whole resulting history (§13.1) and answers 200 `{"head":<head envelope>}`, or 409 with its current head if `from` overlaps different bytes (a fork) or leaves a gap, or 422 with the §1 result. No other authorization is needed: entries are self-authenticating. |

A home MAY accept `Authorization: Colophon <base64url of a call envelope>` in place of a relay
bearer token, with purpose `colophon.home.read` or `colophon.home.write` and audience `{base}`,
verified under §12.3. A bearer token remains storage access only (0.3 §8.1).

## 15. Succession and exit

### 15.1 Predecessor

A genesis MAY name the account its owner continues from:

```json
"predecessor":{"account":"<id>","format":"colophon/authority/5","head":{"seq":12,"digest":"<64 hex>"}}
```

| Field | Rule |
| --- | --- |
| `format` | `colophon/authority/5`, `colophon/authority/4`, or `colophon/swift-keyring/2` (the Swift keyring authority of Marginalia `ColophonAuthority`, 0.1 records). |
| `account` | The predecessor's ID as its format writes it: 64 hex for `/5`, 32 hex otherwise. |
| `head` | The predecessor entry the hand-over is made at: its sequence and the SHA-256 of its exact body. |

The genesis envelope then MUST carry `handover`: signatures over the **genesis body** by
controllers of the predecessor's keyring at `head`, sorted by `signer`, meeting that format's
rule for changing its keyring. A key that is a controller of both accounts signs once; the same
signature bytes MAY appear in the primary set and in `handover`.

- **`/5` and `/4`:** the control rule of that format at `head`, every WebAuthn signature with
  UV, verified under §4.3 with the predecessor's descriptors.
- **`colophon/swift-keyring/2`:** the predecessor's history is Marginalia `ColophonAuthority`
  (reference copy in `reference/swift/Sources/ColophonAuthority`). Its library ID is the first
  32 hex characters of SHA-256 of its first entry's body, and `head.digest` is SHA-256 of the
  exact body at `head.seq`. If the history has adopted a keyring by `head` (a root-signed
  `keyring` entry), `handover` needs at least that keyring's `threshold` distinct controllers
  holding `control`; a `p256` controller signs `raw` (64 bytes) and a `webauthn` controller
  signs as §4.3 with UV, reading its `rpID` as `rp` and with no `origins`. If it has not adopted
  a keyring (a 0.1 root library), `handover` is one `raw` signature whose `signer` is the key ID
  of the root identity's signing key at `head`. This is exactly what that format's own verifier
  (`AuthorityState.verifyKeyringChange`, and `root.verify` before adoption) accepts for a
  keyring change, applied to the 0.5 genesis body.

- A verifier that holds and verifies the predecessor's history up to `head` checks `handover`
  and reports the succession as verified. A verifier that doesn't still verifies the genesis
  under its own control rule, and reports the predecessor as an unverified claim.
- A predecessor never confers anything in the new account: no member, grant or key comes from
  it. Applications that keep their own references to the old ID (for example a Galley
  principal binding) use a verified succession to move them.

### 15.2 Successor

A `/5` account MAY record `successor` (§8.2) under its control rule. A verifier follows a
successor only when the successor's genesis names this account as its verified predecessor.
The old account stays valid and readable.

### 15.3 Clean copy

A copy tool moves records into a new account: it reads a private snapshot with the old
version's own verifier as a member with read access; creates the new account with the owner's
keyring and the same namespaces, naming the old one as `predecessor` with a `handover`; grants
its copying member `write` and `import` with a short expiry; publishes `colophon.importBatch`
units under 0.3 §7.2, with source operation IDs and signed-body digests as encrypted evidence,
never authorship; and reports counts per namespace, view digests and every record it couldn't
copy, with the reason. Grants and members aren't copied; members rejoin. Whoever can read
records can leave with them: a reader who isn't a controller makes the same copy of what it can
open, without a `handover`.

## 16. Upgrading existing accounts

### 16.1 From 0.4, in place

A 0.4 library becomes a 0.5 account by appending one entry, signed by its existing controllers:

```json
{"protocol":"colophon/authority/4","seq":9,"previous":"<64 hex>","issued":"…","by":"<controller ID>",
 "kind":"upgrade","account":"<64 hex>","keyring":{…0.5 keyring…}}
```

- It is a 0.4 entry of a kind 0.4 doesn't know, signed under the 0.4 control rule (every signer
  `control`, at least `threshold`, UV). A 0.4 reader therefore reports `newerFormat` (update
  required) and touches nothing; that is 0.4's own rule (0.4-keys §6.3) and needs no 0.4 change.
- `account` MUST equal the SHA-256 hex of the exact seq-1 body. The full ID begins with the 0.4
  library ID, so anyone holding the old ID and the history can check the hand-over.
- `keyring` MUST equal the prior keyring in `controllers`, `threshold`, `recoverThreshold`,
  `vault` and `slots` (each by canonical JSON, slots in the same order), and add
  `addThreshold` and `policy`. Nothing is rotated and no slot changes, so no passkey ceremony is
  needed beyond the signatures.
- It MUST NOT be seq 2 (0.4's seq-2 rekey rule stands) and appears at most once. Every later
  entry is `/5`.
- Members carry over with their IDs, keys and kinds. A 0.4 grant
  `{namespaces, access, expires?, writeBudget?, import?}` becomes terms
  `{records: [{namespace, access: "write" if access contains "write" else "read"} for each
  namespace], expires, writes: writeBudget, import}`; session numbers start at 0. Epochs, seals
  and slots keep opening unchanged (§7.1, §11.1). Existing records keep their `/3` headers and
  are admitted as before (§11.5).

The upgrading host MUST NOT write the entry until every app that writes to the library is a
0.5 reader: an older app stops at it (safely) until it is updated.

### 16.2 From the Swift keyring authority (Taupe and Marginalia today)

Libraries made by the shipped apps use Marginalia's Swift `ColophonAuthority` with 0.1
records, not 0.4: a 0.1 genesis naming a root and a recovery identity, optionally followed by
a root-signed `keyring` entry that adopts controllers, after which controllers sign grants,
revocations, key shares, layout and keyring changes. Both states exist in the format. They move
by clean copy (§15.3) into a new 0.5 account with `predecessor.format`
`colophon/swift-keyring/2` and `predecessor.account` the 32-hex library ID:

- The new genesis keyring reuses the old controllers' public keys: the same passkeys, security
  keys, device owner keys and kit, with the same key IDs and the person's chosen roles. **No new
  passkey and no new account at the identity service are created**; the passkey's existing
  WebAuthn `user.id` stays as it was, which §17.4 allows.
- Each passkey or security key with PRF needs one assertion to build its new `prf` slot (the
  old slots use the Swift labels and can't be reused). Sealed slots for device keys and the kit
  are built from their public agreement keys without a ceremony.
- The old control quorum (or, for a root library, the root identity) signs `handover` over the
  new genesis (§15.1). A passkey that is a controller of both signs once. A root library's root
  is a device key in the app; it signs without a passkey prompt.
- Members (apps on each device, agents) rejoin with new grants; the controller device approves
  them in one session. Records are copied with evidence and accounted for (§15.3); nothing is
  dropped silently.

The new account ID differs from the old library ID. The verified succession (§15.1) is the
signed hand-over any verifier with the old history can follow.

## 17. Host interface

Names are informative; behaviour is normative.

### 17.1 Authority changes

1. **Unlock first.** An action that reads or seals epochs needs the vault seed in the session
   first. The core reports which slots the available keys can open, with PRF salts and HPKE
   `enc` values; the host returns PRF outputs and ECDH secrets; the core opens and checks.
2. **New PRF slots need PRF before the body** (§7.2).
3. **Prepare.** The core returns the exact body, which signers can satisfy §8.4 among the host's
   keys under each rule, and the WebAuthn challenge (SHA-256 of the body) for each.
4. **Finish.** The host returns signatures and assertions; the core verifies §4 and §8 before
   returning the record. Nothing is written on any failure.
5. **Prompts.** Each distinct body needs its own WebAuthn assertion. A `raw` hardware key with
   an authenticated context (Secure Enclave with LAContext, Android Keystore auth validity)
   SHOULD sign every body of one action under one presence check.

### 17.2 Calls, links and heads

- **Calls.** The core prepares the call body from the host's purpose, audience and arguments,
  and the host's random `requestId`; the host signs; the core can verify any call under §12.3
  given the account's history, fresh heads, the clock and the host's replay record.
- **Links.** A member's host creates a session key, has the core prepare the link, signs it with
  the member key, and keeps the session private key only as long as the link lasts.
- **Heads.** A home's host has the core prepare a head over its verified history and signs it
  with the home's member key.
- **Standalone checks.** The core exposes, on every binding, a pure verifier for a complete
  history that needs no host identity or key (returning the account ID and legacy ID if
  upgraded; the head `{seq, digest}`; each controller ever present with its descriptor, roles,
  and first and last sequence; each member with its keys, kind, label, terms in force, grant
  `{seq, digest}`, renewal sequences, session number and revoked sequence; homes with keys and
  endpoints; the keyring thresholds and policy; and any verified predecessor or successor), a
  standalone WebAuthn check (§4.3) taking a descriptor, body, signature, authenticator data,
  client data and whether UV is required, returning `ok` with the UV bit or `badSignature` with
  a diagnostic naming the failed check, and the call and head verifiers of §12.3 and §13.3.
  A verifier MAY start from a history it has already verified and persisted, and verify only
  the entries after it.
- **Vault seals for other formats.** The core MAY open an HPKE (§11.1 suite) seal addressed to
  the vault's agreement key whose `info` does **not** begin with `colophon/`, for formats outside
  Colophon such as backups. HPKE binds `info` into its key schedule, so this never opens a
  Colophon seal. The core never exports the seed or a raw ECDH output of the vault key.

### 17.3 Adding a key

**Adding a passkey on a new platform is one approval by an existing controller,** with the
keyring's default `addThreshold` of 1:

1. The new device registers the passkey (§3.5), with UV required and attestation none, and
   performs one assertion restricted to it with a fresh salt over a fresh core challenge.
2. If the new device doesn't hold the seed, the seed moves to it under §7.3 after the person
   confirms the pairing code. The new device's core builds the `prf` slot and checks it opens.
3. An existing controller (on that device or another) signs one `keyring` entry that only adds
   the new controller and its slot, under the add rule.

A key without PRF is added without a slot and shown as able to approve but not to unlock. A
security key is added the same way, with `recover` among its roles when the person wants it as
a recovery key.

### 17.4 WebAuthn user handles

`user.id` is chosen at registration and never changes. Hosts SHOULD set it to the UTF-8 bytes of
the 64-character account ID when the credential is created for an existing account, and to 32
random bytes when it is created before the account exists. It is a lookup hint only: a verifier
finds the controller by `rp` and `credential` and MUST NOT require any particular `user.id`. A
key added to further accounts keeps its first `user.id`.

### 17.5 Notices

Every entry under the add or recovery rule, every controller removal, every `successor` and
every policy change SHOULD be shown on every other device that holds a controller of the
account, with who signed it, when, and a way to answer *That was me* or *Remove it*. A host
SHOULD NOT tell the person a keyring change is done until at least one home holds it.

## 18. Policy fields and defaults

Colophon fixes the field, its range, its default and who may change it. A host is a reference
implementation of these defaults; another host may ship different defaults within the ranges.

| Field | Where | Default | Range | Changed by |
| --- | --- | --- | --- | --- |
| `threshold` | keyring | 1 | 1 … `control` controllers | control rule |
| `recoverThreshold` | keyring | 1 (any one recovery controller) when any controller has `recover`, else 0 | 0, or 1 … `recover` controllers (m of n) | control rule |
| `addThreshold` | keyring | 1 | 1 … `threshold` | control rule |
| `policy.headMaxAge` | keyring | 300 s | 30–86,400 s | control rule |
| `policy.headQuorum` | keyring | 1 | 1–8 | control rule |
| `policy.callWindow` | keyring | 300 s | 30–3,600 s | control rule |
| `policy.linkMaxAge` | keyring | 86,400 s | 60–2,592,000 s | control rule |
| `policy.history` | keyring | `members` | `members`, `public` | control rule |
| Number and kinds of controllers | keyring | below | 1–64, `raw` or `webauthn` | control rule; adding only, under the add or recovery rule |
| Roles of an added controller | the entry | below | any non-empty subset, within §8.4's add and recovery limits | the signers of that entry |
| `verification` | controller | `true` for every `webauthn` controller | present or absent | control rule |
| `origins`, `authorityOrigins` | controller | absent | §3.1 | control rule |
| Member `expires` | terms | 7 days for `agent`, none for `device` and `app` | any, or absent | approver at grant; `renew` |
| Member `depth` | terms | 0 (1 for `agent`, so it can make sessions) | 0–4 | approver at grant |
| Member `writes` | terms | absent | 0 … 2^53−1 | approver at grant |
| Homes | grants | none; a host that offers a home appoints it when the person enables it | 0–8 | control rule |

**Reference setups** (host defaults, not protocol rules):

| Controller | Person | Company |
| --- | --- | --- |
| Each device owner key | `approve`, `control`; sealed slot | `approve`, `control` for each founder's device; sealed slot |
| Each passkey (one per platform or password manager) | `approve`, `control`; `prf` slot when PRF works | each founder's passkey, `approve`, `control` |
| Security keys | two, each `approve`, `recover`; `prf` slot where the platform delivers it | two per founder, `approve`, `recover` |
| Thresholds | `threshold` 1, `recoverThreshold` 1, `addThreshold` 1 | `threshold` 2 when two or more people hold `control`, else 1; `recoverThreshold` 2 when there are two or more recovery keys held by different people, else 1; `addThreshold` 1 |

A company is its own account. Its controllers are keys held by its people, often the same
passkeys and security keys that control their personal accounts. Hosts warn (§6.4) until a
person has two recovery controllers and at least one of them has a slot.

## 19. Results and reasons

| Where | Reasons |
| --- | --- |
| Authority (§8) | `malformed`, `badSignature`, `newerFormat` |
| Slots (§7) | `refused:vaultLocked` |
| Records (§11.5) | refused `notGranted`, `expired`, `revoked`, `wrongEpoch`, `clockJump`, `budgetSpent`, `outOfScope`, `invalidPayload`, `duplicateID`, `wrongFormat`, `budgetScopeUnavailable`; held `revokedBackdated`, `authorityBehind`, `unavailable` |
| Calls (§12.3) | `refused:audience`, `refused:window`, `refused:conflict`, `refused:fork`, `refused:revoked`, `refused:expired`, `refused:ended`, `refused:notNarrower`, `refused:outOfScope`; `unavailable` |
| Heads (§13.3) | `refused:fork`, `refused:rollback`; `unavailable` |

Inside an envelope, any failure while verifying an attached signature is `badSignature`,
whatever check failed. Implementations MAY expose the failed check as a diagnostic.

## 20. Not in this version

Each of these is an extension: a new kind, term, form, policy field or protocol marker that a
0.5 reader meets as authenticated unknown content and reports as `newerFormat`. None changes a
format above.

- Accounts as controllers of other accounts, and cross-account signatures.
- Guarded state: an appointed authority ordering transitions, exclusive claims, spending limits.
- Modules as published WASM, releases, attestations, adoption and the layered agreement.
- Records authored by session keys; epoch-key hand-off to sessions.
- Terms that require evidence about the acting key (`requires`), and signed custody or
  presence, until attestation exists.
- Signed history checkpoints that let a verifier skip entries.
- Independent witnesses beyond `headQuorum`.
- Pre-rotation of keys.
- Proposals into a namespace the proposer can't read.

The reasons are in [colophon-0.5-changes.md](colophon-0.5-changes.md) §C.

## 21. Conformance

0.5 freezes only after these vectors are published under `conformance/0.5/` with exact input
bytes, intermediate values and one named outcome per refuse case, and an implementation passes
them. `conformance/0.5/candidate/` holds the subset that could be produced before
implementation; [the implementation plan](colophon-0.5-implementation.md) lists the rest.

- **Every 0.4 key case,** re-expressed as `/5` (genesis, thresholds, WebAuthn checks, slots,
  rotation, recovery, unknown kinds, parsing, DER), with the same outcomes, plus the 0.4 cases
  replayed unchanged as the legacy prefix of an upgraded account.
- **Identifiers:** 64-hex IDs; the 0.4 prefix relation; a 32-hex reference refused; hints with
  redirects, private destinations and DNS rebinding (host test).
- **Upgrade:** accepted upgrade; a 0.4 reader's `newerFormat` on it; wrong `account`; changed
  keyring field; approve-only signer; upgrade at seq 2; a second upgrade; a `/4` entry after it;
  a `/5` entry before it; `/3` record citing after the upgrade; `/5` record citing before it.
- **Keyring rules:** add rule adding a passkey with one signature; add rule exceeding its role
  limits; add rule changing policy; recovery rule unchanged from 0.4; policy change under the
  control rule; out-of-range policy; `authorityOrigins` with an authority entry from a listed
  and from an unlisted origin, and a call from the unlisted origin (accepted); an
  `authorityOrigins` entry the descriptor doesn't allow; a web origin in `origins`; a web origin
  with a port.
- **Members:** grant covered and not covered by the request; per-namespace access; `serves`
  under the single rule; `serves` to an agent; import rules from 0.4; renew under the single
  rule and of an import member; revoke with `kept` and `heads`, a record on and off the kept
  chain, a forked chain; `endSessions` by approver, by the member, by another member.
- **Records:** propose admitted not folded; accept, duplicate accept, accept and decline in both
  orders; `kinds` and `conditions` refusal reserving budget; author chain `previous`.
- **Terms:** every narrowing rule passing and failing; every predicate; each bound at and
  beyond its limit; mixed integer and binary64 comparison at 2^53 and 2^53+1.
- **Calls:** member with no links; three links; controller call with an assertion; wrong
  audience; outside the window; replay identical and conflicting; asOf fork; no fresh head;
  quorum of two with one stale; revoked member; expired member; ended session; link widening;
  link outliving its parent; depth exceeded; copied link with another key; invalid call
  signature before any fetch; unknown field after valid and after invalid signatures.
- **Heads:** valid; stale; signed by a non-home; equivocation; rollback below the high-water
  mark; fork against held history.
- **Succession:** verified `/5` and `/4` predecessors; handover short of the predecessor's
  threshold; predecessor unverifiable (reported, not refused); successor followed only with a
  matching predecessor.
- **Seed transfer:** wrong account in `info`; wrong ephemeral key.

## 22. Review log

| Date | Reviewer | Findings | Resolution |
| --- | --- | --- | --- |
| 2026-11-11 | — | Final candidate written from 0.4, Galley drafts 1–2, the adversarial review, the W0 closure matrix, the W1 findings and Galley's one-identity contract | Awaiting independent review |
