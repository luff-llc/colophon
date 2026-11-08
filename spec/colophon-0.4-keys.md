# Colophon 0.4 (draft): keys and the keyring

**Status: S2 specification, draft 3, 2026-11-08 (interface frozen pending §10 vectors).** Revised after independent reviews by Codex
and agy ([review log](#12-review-log)). Not implemented. When accepted, this text is folded into
`colophon-0.4.md`.

This document replaces Colophon 0.3 §2 (private-key steps), §3 (who epochs are sealed to), §4
(authority) and the root-only rule in §7.2. Operations, modules, live state, blobs and HTTP
exchange (§5–§8) are otherwise unchanged. Requirements and rationale: Galley F2
(`luff-llc/galley`, `docs/foundations/f2-keys.md`, private).

MUST, SHOULD and MAY express protocol requirements. Every MUST has a conformance vector (§10).
Backward compatibility with 0.1 or 0.3 records is **not** a goal. Older libraries become 0.4
libraries by clean copy (§9).

## 1. What changes from 0.3

| Change | Reason |
| --- | --- |
| A **keyring of controllers** replaces the root and the recovery identity. Controllers are passkeys, security keys, device owner keys and recovery kits, with roles and thresholds. | No single key is the library. |
| Authority signatures come in two **forms**, `raw` P-256 and `webauthn` assertions, and authority records can carry **cosignatures**. | Passkeys can't sign arbitrary bytes. Thresholds need several signatures over one body. |
| A **vault** identity receives every new epoch, in place of root and recovery. Its seed is opened through **slots**. | Controllers change without resharing epochs to each one. Passkeys unlock data through PRF. |
| `reshare`, `handover` and `recover` are removed. One `keyring` entry makes every authority change. | One verified rule instead of three special cases. |
| **Controllers aren't members**, and **no key serves two principals.** Agents and servers can never be controllers. | Authority and content authorship are separate. Agents never hold authority. |
| The 0.3 root-only import permission becomes an explicit **`import` grant**. | There is no root. Import power is granted, scoped and expiring. |

These are unchanged: member identities and kinds, requests, the pairing code, grant fields
other than `import`, HPKE epochs, operations (`/3` markers), live state, layout values,
canonical JSON (0.3 §2), and the HTTP exchange. Authority bodies use
`protocol: "colophon/authority/4"`.

## 2. Parsing and keys

### 2.1 Strict parsing

All protocol JSON, including `clientData` and operation payloads, MUST be rejected with
`malformed` if any object, at any depth, has a duplicate member name.

**Closed field sets.** Authority bodies, envelopes, keyrings, controllers, key descriptors,
slots and parts have exactly the fields this document lists. Optional fields MUST be omitted
when absent. In these objects, `null` is allowed only for `previous` at genesis. Empty arrays
are not allowed where this document says "non-empty". A field of the wrong type is `malformed`.
An unknown field is handled by the verification order in §6.3: it's `newerFormat` only after
authorization. Operation payloads, import evidence and module values follow their own schemas
and MAY contain `null`. Unknown `clientData` members are ignored.

### 2.2 Key descriptor

```json
{"form":"raw","signing":"<base64>","agreement":"<base64>"}
{"form":"webauthn","signing":"<base64>","rp":"id.luff.works","credential":"<base64>"}
```

| Field | Rule |
| --- | --- |
| `form` | `raw` or `webauthn` |
| `signing` | A valid, uncompressed 65-byte P-256 point |
| `agreement` | `raw` only, and optional. A valid 65-byte P-256 point. Required when the key opens a `sealed` slot or part. MUST be absent for `webauthn`. |
| `rp` | `webauthn` only, and required. It's 1–253 bytes: dot-separated labels of 1–63 lowercase ASCII letters, digits and `-`, where no label starts or ends with `-`. |
| `credential` | `webauthn` only, and required. 1–1023 bytes. It's a lookup hint and MUST NOT affect verification. |
| `origins` | `webauthn` only, and optional. 1–32 strings, each 1–512 printable ASCII bytes (`0x21`–`0x7E`), in strictly ascending byte order, for example `android:apk-key-hash:<base64url>` (§3.3). An entry MUST NOT start with `http:` or `https:`, because web origins come only from `rp`. |

The key ID is the first 32 lowercase hex characters of SHA-256 of the `signing` bytes.

### 2.3 One key, one principal

A **principal** is one controller (by ID), one member (by ID), or one vault generation. Across
the library's whole history:

1. Within a principal, `signing` and `agreement` MUST be different points.
2. Every P-256 point, used for signing or agreement, and every key ID belongs to **exactly one
   principal and one usage**. No two principals may share a point or a key ID, within a
   category or across categories, and no signing point may equal any agreement point.
3. A principal may repeat its own keys only by staying the same principal: a retained
   controller, or the unchanged current vault.

An authority entry that would introduce a collision is `malformed`. Devices therefore use
**separate** owner (controller) keys and member keys. The Swift apps already do this with
`root.json` and `identity.json`.

### 2.4 Private-key work stays in the host

The core holds no platform private key. Every signature, ECDH and PRF evaluation is
two-phase: `begin_*` returns the exact input, and `finish_*` verifies the result before using
it. The **vault seed** is a library secret, not a platform key. The core MAY hold it in memory
for a session, and MUST NOT persist it. The host persists the seed only inside slots.

### 2.5 COSE_Key at registration

The credential public key MUST be a definite-length CBOR map with exactly five entries and no
duplicate keys:

- 1 (kty) = 2;
- 3 (alg) = −7;
- −1 (crv) = 1;
- −2 (x) and −3 (y), each a 32-byte byte string.

Integers and lengths MUST use minimal encoding, and nothing may follow the map. The key is
`0x04 ‖ x ‖ y`, and it MUST be a valid point. Anything else is `malformed`. Attestation MAY be
recorded and MUST NOT be required.

## 3. Authority signatures

This section applies **only** to `colophon/authority/4` envelopes. Requests and operations keep
the 0.3 single raw member signature. They MUST NOT carry `assertion` or `cosignatures`, and
those fields on them are `malformed`.

### 3.1 Envelope

```json
{"body":"<base64>","signature":"<base64>",
 "assertion":{"authenticatorData":"<base64>","clientData":"<base64>"},
 "cosignatures":[{"signer":"<keyID>","signature":"<base64>","assertion":{...}}]}
```

- `assertion` is present if and only if the primary signer's form is `webauthn`. The same
  holds for each cosignature.
- `cosignatures` is either absent or non-empty, sorted by `signer`.
- The primary signer is the body's `by`. Cosigners MUST be distinct from each other and from
  `by`.
- Every attached signature MUST verify, and MUST be by a controller of the keyring that
  authorizes the entry (§6.3). One failing or foreign signature makes the whole entry
  `badSignature`.

### 3.2 `raw`

`signature` is 64 bytes, `r ‖ s`. It's ES256: ECDSA P-256 over SHA-256 of the exact `body`.

### 3.3 `webauthn`

A verifier MUST check, in order:

1. `clientData` parses under §2.1 and contains:
   - `type` equal to `"webauthn.get"`;
   - `challenge` equal to the unpadded base64url of SHA-256(`body`);
   - an allowed `origin` (below);
   - `crossOrigin` absent or `false`.

   Other members are ignored.
2. `authenticatorData` is at least 37 bytes, and bytes 0–31 equal SHA-256 of the UTF-8 `rp`.
3. The flags byte (32) has UP (`0x01`) set. UV (`0x04`) MUST be set when the controller has
   `verification: true`, and for every signature on `genesis`, `keyring`, `layout`, and on a
   `grant` with `import` (§7).
4. The sign counter is ignored.
5. Let `M = authenticatorData ‖ SHA-256(clientData bytes)`. `signature` MUST be exactly
   `0x30 ‖ len ‖ 0x02 ‖ rlen ‖ r ‖ 0x02 ‖ slen ‖ s`, with nothing after it. Every length is a
   single byte below `0x80`, and `len = rlen + slen + 4`. `r` and `s` are each 1–33 bytes, with
   the first byte at most `0x7F`. A leading `0x00` is allowed only when the next byte is
   `0x80` or higher. Both decode big-endian to values in [1, n−1]. It's verified as ES256 over SHA-256(M).
   A message API receives `M`; a prehashed API receives SHA-256(M). High-S values are
   valid. A library that enforces low-S (for example Rust `p256`) MUST normalize `s` to
   `min(s, n−s)` after the DER checks and before verifying. The stored bytes are never changed.

**Allowed origins:** either
- `https://` followed by a host, with no port, path, query, fragment or user information
  (none of `/ : ? # @ \`), where the host equals `rp` or ends with `.` ‖ `rp` with a
  non-empty prefix that doesn't start or end with `.` and doesn't contain `..`; or
- an exact member of the controller's `origins`.

Verifiers MUST NOT rewrite `clientData`.

## 4. Controllers and the keyring

### 4.1 Controller

```json
{"key":{...},"label":"Passkey","roles":["approve","recover"],"verification":true}
```

| Field | Rule |
| --- | --- |
| `roles` | A non-empty, sorted, duplicate-free subset of `approve`, `control` and `recover` |
| `verification` | `webauthn` only. Present only as `true`. |
| `label` | 1–200 bytes. Display only. |

The controller ID is the key ID. Because of §2.3, no controller key can be a member, so agents
and servers can never be controllers.

### 4.2 Keyring

```json
{"controllers":[...],"threshold":1,"recoverThreshold":1,"vault":{"signing":"…","agreement":"…"},"slots":[...]}
```

- `controllers`: non-empty, sorted by ID, with no duplicates. At least one has `control`.
- `threshold`: an integer, at least 1, at most the number of `control` controllers.
- `recoverThreshold`: an integer, always present. It's 0 if no controller has `recover`, and
  otherwise between 1 and the number of `recover` controllers. It MAY exceed `threshold`.
  Unlike the Swift 0.1 reference, 0.4 sets no ordering between the two thresholds. The
  approve-only limit in §6.3 is what keeps recovery from manufacturing control.
- `vault`: a public identity (§5.1).
- `slots`: non-empty, each valid under §5.2.

Hosts SHOULD warn when losing any single key would leave either no signing quorum or no
openable slot.

## 5. Vault and slots

### 5.1 Vault

The vault seed is 32 random bytes from the host. Its identity is derived like a 0.3 recovery
kit: first `s' = HKDF-SHA256(IKM = seed, salt = "colophon/vault/4", info = "identity", 32 bytes)`,
then the unchanged 0.3 §2 software-identity procedure on `s'` (salt `colophon/entropy/3`,
counters from zero).

**Each newly introduced epoch MUST be sealed to exactly the current vault and the active,
unexpired members with read access to its namespace, at the introducing entry.** Historical
seals stay valid authenticated history. Later `shares` add only the recipients this document
authorizes.

After opening any slot, the core MUST check the plaintext is 32 bytes, derive the identity,
and compare both public keys with the keyring's `vault`. A mismatch is `vaultLocked`, and the
session's unlocked seed is left unchanged.

### 5.2 Slots

Every slot has exactly these fields: `kind`, `controllers` (IDs of current controllers),
`label` (1–200 bytes) and its kind's own fields:

```json
{"kind":"sealed","controllers":["<id>"],"label":"iPhone","sealed":{"enc":"<base64>","ciphertext":"<base64>"}}
{"kind":"prf","controllers":["<id>"],"label":"Passkey","salt":"<base64>","box":"<base64>"}
{"kind":"combined","controllers":["<id0>","<id1>"],"label":"Kit and passkey",
 "parts":[{"kind":"sealed","sealed":{"enc":"<base64>","ciphertext":"<base64>"}},{"kind":"prf","salt":"<base64>"}],
 "box":"<base64>"}
```

Part indices are zero-based. Every part secret is exactly 32 bytes, and they're concatenated as
`S0 ‖ … ‖ S(n−1)`. Slot info strings bind the vault and the controllers, but not the library ID,
so genesis can carry slots without circularity. The vault is fresh per library (§6.2), which
makes the binding library-specific.

```text
I  = "colophon/vault-slot/4\n" ‖ vaultID ‖ "\n" ‖ kind ‖ "\n" ‖ join(controllers, ",")
Ii = "colophon/vault-part/4\n" ‖ vaultID ‖ "\n" ‖ decimal(i) ‖ "\n" ‖ part.kind ‖ "\n" ‖ controllers[i]
```

| Kind | Shape | Opening |
| --- | --- | --- |
| `sealed` | One controller, `raw` with `agreement`. `sealed` is `{enc (65-byte point), ciphertext (48 bytes)}`. | HPKE (0.3 §3 suite) to that agreement key, with `info` and AAD `I`. The plaintext is the seed. |
| `prf` | One controller, `webauthn`. `salt` (32 bytes), `box` (60 bytes). | PRF output `P` (below). Key = HKDF-SHA256(IKM `P`, salt `salt`, info `I`, 32 bytes). `box` = nonce(12) ‖ AES-256-GCM(seed, AAD `I`) ‖ tag. |
| `combined` | At least 2 distinct controllers. `parts` has the same length and order. `box` is 60 bytes. Part `i` is `{"kind":"sealed","sealed":…}` for a `raw` controller with `agreement`, or `{"kind":"prf","salt":…}` for a `webauthn` controller. | Part secret `Si`: a sealed part is HPKE with `info` and AAD `Ii`; a prf part is HKDF(IKM `P`, salt, info `Ii`). Key = HKDF-SHA256(IKM `S0 ‖ … ‖ Sn`, salt empty, info `I`, 32 bytes), then the `box` as for `prf`. |

Each sealed part MUST encrypt a fresh, independent random 32-byte secret, never the seed and
never reused. A wrong secret is `vaultLocked`. Structural violations are `malformed` at replay,
not when the slot is first opened.

**PRF bytes.** `salt` is the exact WebAuthn PRF extension input (`prf.eval.first`). `P` is the
32-byte `results.first`. A host that talks CTAP `hmac-secret` directly MUST apply the WebAuthn
transformation, SHA-256(`"WebAuthn PRF"` ‖ 0x00 ‖ salt), and select the UV-associated
secret. If PRF is unsupported or returns no result, that MUST fail explicitly. There's no
fallback derivation.

**Building a new PRF route.** A PRF output used to build a `prf` slot or part MUST come from an
**assertion** (`get`) restricted to exactly that slot's credential, evaluating the slot's
`salt`, and signing a fresh challenge from the core. Registration-time PRF outputs MUST NOT be
used, because many platforms don't evaluate PRF at registration. The core MUST verify that
assertion's signature against the new controller's key before building the slot. This binds
the credential. It doesn't authenticate the PRF bytes, which the host is trusted to pass
through unchanged from the platform. After building the slot, the core MUST open it with the
same output and check the vault (§5.1) before the slot is published. Adding a passkey therefore
takes a registration and one assertion. The authority body is signed by an existing controller
(normally a device owner key) unless the passkey is the only signer available.

## 6. Authority

### 6.1 Body

Each authority body contains:

- `protocol: "colophon/authority/4"`;
- contiguous `seq` from 1;
- `previous`: SHA-256 hex of the exact preceding body, `null` only at genesis;
- `issued` (0.3 date format);
- `by`: the primary signer's controller ID;
- `kind`, and that kind's fields.

The library ID is the first 32 hex characters of SHA-256 of the exact genesis body.

### 6.2 Kinds

| Kind | Fields | Effect |
| --- | --- | --- |
| `genesis` | `label`, `namespaces`, `keyring`, optional `importedFrom` (32 lowercase hex, display only, §9) | Creates the library and its first keyring. The vault MUST be fresh. |
| `rekey` | `epochs` (non-empty) | Introduces consecutive epochs (§5.1). A library with only `genesis` is valid and has no epochs. **If seq 2 exists, it MUST be a `rekey` introducing epoch 1 for exactly the declared namespaces.** |
| `grant` | `request`, `grant`, `shares` | As 0.3, plus optional `import` (§7) |
| `revoke` | `memberID`, `kept`, `epochs` | As 0.3. New epochs are sealed per §5.1. |
| `keyring` | `keyring`, and `shares` plus `epochs` only if the vault changes | Replaces the keyring wholesale. If `keyring.vault` is unchanged, `shares` and `epochs` MUST be absent. If it changes: the new vault MUST be fresh (§2.3); `shares` MUST seal every existing epoch to the new vault; and `epochs` MUST introduce a new epoch in every namespace. |
| `layout` | `layout` | As 0.3. It never lowers the layout. |

**When the vault is unchanged, every existing slot MUST stay**, compared as a multiset by
canonical JSON of the slot without `label`. Slot order and labels MAY change, and slots MAY be
added.

**Rotation is required** when any of these happens to a controller present before the entry:

- it's absent afterwards;
- it loses any role;
- its `agreement` key changes or is removed;
- any existing slot is deleted or its cryptographic fields change.

A controller that stays with fewer roles MAY have slots for the new vault. A removed
controller can't be named by a slot (§4.2). Historical slots keep opening their original
vault. Deleting a slot never revokes knowledge of that seed, which is why deletion forces
rotation. Changing only `label`, `verification`, `credential` or `origins` doesn't require
rotation, but it is a control-rule change. A properly signed entry that omits a required
rotation is `malformed`.

### 6.3 Who may sign what

Signers of every entry except `genesis` are evaluated against the keyring **before** the entry.
Genesis signers are evaluated against the genesis keyring.

| Kind | Rule |
| --- | --- |
| `genesis` | **Control rule** over the new keyring |
| `keyring` | **Control rule.** If that fails, the **recovery rule** applies. If both fail, `badSignature`. |
| `layout` | **Control rule** |
| `grant` with `import` | **Control rule** |
| `rekey`, `grant`, `revoke` | **Single rule:** exactly one signer, no cosignatures, holding `approve`. For `rekey`, holding `control` is also enough. |

- **Control rule:** every signer holds `control`, the number of distinct signers is at least
  `threshold`, and every WebAuthn signature has UV.
- **Recovery rule:** `recoverThreshold > 0`; every signer holds `recover`; the number of distinct
  signers is at least `recoverThreshold`; every WebAuthn signature has UV; and the change **only
  adds**:
  - every existing controller is identical by canonical JSON of the whole controller;
  - `threshold`, `recoverThreshold` and `vault` are unchanged;
  - every existing slot is preserved as a multiset by canonical JSON, including its label,
    though positions may change;
  - only new controllers, and slots naming only new controllers, are added.

  **If `recoverThreshold < threshold`, every added controller MUST have roles exactly
  `["approve"]`.**

**Verification order.** For seq > 1, the verifier MUST, in this order:

1. Parse the envelope and body as generic JSON (duplicate names rejected). Then check the
   common header: `protocol`, `seq` (the next number), `previous` (the last digest), `issued`,
   and `by` (a controller in the prior keyring).
2. Verify every attached signature against the prior keyring (§3). Any failure is
   `badSignature`.
3. Decide the rule:
   - a known `kind` uses its rule from the table above;
   - an **unknown** `kind` requires the **control rule**.

   If the rule isn't met, the result is `badSignature`.
4. Only now look for unknown content: an unknown `kind`, an unknown field, or an unknown
   `form`, role, slot kind or part kind anywhere in the body. If any is found, the result is
   `newerFormat`.
5. Otherwise, apply the full typed schema and the §6.2 transition rules. A violation is
   `malformed`.

So an entry only one minority controller signed can never force an update prompt, and an
unauthenticated one always fails with `badSignature` or `malformed`. For genesis, unknown
values in its own keyring are `newerFormat`. A forged genesis can't enter an existing library,
because the library ID is the genesis digest.

## 7. Members

Requests, member kinds, the pairing code, expiry and write budgets work as in 0.3 §4. Grants
are signed per §6.3. **Controllers aren't members.** Genesis creates no member. A device that
writes content needs a member identity and a grant, normally approved in the same session it
creates the library.

`grant.import` (boolean, present only as `true`) lets that member publish
`colophon.importBatch` (0.3 §7.2) in the granted namespaces. In 0.4, every 0.3 rule that names
the root's import role names this grant instead. Requests are unchanged and never carry
`import`. Only the approving controllers add it. An import grant:

- MUST include `write` in `access`;
- MUST have `expires` later than the entry's `issued`;
- MUST be signed under the control rule;
- MUST be for a member whose request `kind` is `device` or `app`.

Any violation is `malformed`, or `badSignature` if the rule isn't met.

Import expiry works like ordinary operation expiry. Remote admission compares the parent's
signed `created` with `expires`, and local creation checks the host's current time. Expiry
doesn't prove publication time. To stop accepting further imports, revoke the copying member
and list the accepted parent-body digests in `kept`. Readers MUST NOT use the time they first
saw a record as an admission rule. Admitted imports keep their evidence attribution, which
never becomes destination authorship or authority.

## 8. Host interface

Names are informative; the behavior is normative.

1. **Unlock first.** An action that reads or seals epochs (`grant`, `revoke`, vault-rotating
   `keyring`, `rekey`) needs the vault seed in the session first. The core reports which slots
   the available keys can open, with their PRF salts and HPKE `enc` values. The host returns
   PRF outputs and ECDH secrets, and the core opens and checks the slot (§5.1).
2. **New PRF slots need PRF before the body.** To create a `prf` slot or part, the host
   performs the assertion described in §5.2 ("Building a new PRF route") before the core
   builds the entry.
3. **Prepare.** The core returns the exact body, which signers can satisfy §6.3 among the
   host's available keys, and the WebAuthn challenge (SHA-256(body)) for each.
4. **Finish.** The host returns the signatures and assertions. The core verifies §3 and §6.3
   before returning the record, and nothing is written on any failure.
5. **Prompts.** Each distinct body needs its own WebAuthn assertion. A `raw` hardware key that
   supports an authenticated context (Secure Enclave with LAContext, Android Keystore auth
   validity) SHOULD sign every body of one action under one presence check. Hosts SHOULD
   design actions to need one authority body where possible. For example, creating a library
   with a device owner key needs presence once; adding a passkey later is one more ceremony.

## 9. Clean copy from older libraries

A 0.4 verifier never reads 0.1 or 0.3 authority. A copy tool:

1. Reads a private snapshot of the old library, never the original. It reads with that
   version's own verifier, as a member with read access. Proving the old root isn't needed.
2. Creates a **new** 0.4 library: a new library ID, a keyring the person sets up, and the same
   namespaces.
3. Grants its copying member read and write access plus `import`, with a short expiry, and
   publishes `colophon.importBatch` units under the 0.3 §7.2 contract. Source operation IDs and
   exact signed-body digests are encrypted evidence inside the batch, never authorship.
4. Reports counts per namespace, view digests, and every record it couldn't copy, with the
   reason.

Grants, members and agents aren't copied. The genesis MAY carry `importedFrom: "<old library
ID>"` as a signed, display-only claim. It confers nothing.

## 10. Conformance

**The spec freezes as v1 only after these vectors are published** with exact input bytes,
intermediate cryptographic values (slot and part keys, PRF-derived keys, HPKE shared secrets)
and one named outcome per refuse case. Vectors in `conformance/0.4/keys/` use published software keys and a synthetic WebAuthn
authenticator: a fixed P-256 key, `authenticatorData = SHA-256(rp) ‖ flags ‖ 00000000`,
`clientData` built from the challenge, and both high-S and low-S signatures. Each refuse case
names its outcome.

**Accept cases:**

- Genesis with one raw controller.
- Genesis with threshold 2 (raw plus WebAuthn).
- Seq-2 rekey.
- A passkey-signed grant.
- An import grant under the control rule.
- Rekey signed by a control-only controller.
- Recovery that only adds, with an approve-only addition when `recoverThreshold < threshold`.
- Removal with rotation; the new vault reads history.
- Demotion with rotation; the demoted controller keeps a new slot.
- `prf`, `sealed` and two-part `combined` slots opened.
- A multi-label subdomain origin.
- An allowlisted Android origin.
- A high-S WebAuthn signature.
- A genesis-only library.
- `recoverThreshold` greater than `threshold`.
- Slot reordering and relabeling without rotation.
- An unknown kind signed under the control rule (`newerFormat`).
- A `null` inside an operation payload.

**Refuse cases:**

- WebAuthn: wrong challenge; wrong RP hash; foreign origin; origin with user information or a
  port; `crossOrigin: true`; `webauthn.create`; UP missing; UV missing where required;
  non-minimal DER; another controller's key.
- Rules:
  - threshold unmet;
  - mixed-role signers;
  - an invalid extra cosignature;
  - cosignatures on a single-rule kind;
  - `recoverThreshold` 0 used for recovery;
  - recovery adding `control` while `recoverThreshold < threshold`;
  - recovery that removes, demotes, changes a threshold or changes the vault;
  - removal or demotion without rotation;
  - vault reuse (A→B→A);
  - `shares` present without a vault change;
  - layout with one of two required signatures;
  - import grant under the single rule, or to an agent.
- Keys and slots:
  - a key in two principals (controller and member, member and vault);
  - an empty or one-part combined slot;
  - duplicate controllers in a combined slot;
  - a `prf` slot naming a raw controller;
  - wrong sizes;
  - a slot that opens to a seed for another vault;
  - a wrong PRF output.
- Parsing and order:
  - duplicate JSON names (body and `clientData`);
  - COSE with extra or duplicate keys, or trailing bytes;
  - an empty `cosignatures` array;
  - an unauthenticated unknown kind (`badSignature`, not `newerFormat`);
  - an authenticated unknown kind (`newerFormat`);
  - seq 2 not a full rekey;
  - a 0.3 authority body;
  - an unknown kind signed by one approve controller (`badSignature`);
  - an unknown field on a controller under the single rule (`badSignature`);
  - DER with long-form length, trailing bytes or extra padding.
- Additional keys and slots:
  - two controllers sharing an agreement point;
  - `signing` equal to `agreement`;
  - slot deletion without rotation;
  - agreement change without rotation;
  - recovery that drops a duplicate slot;
  - a PRF slot built from a registration output (host-side check);
  - an `origins` entry starting with `https:`;
  - an `rp` label starting with `-`.
- Additional grants and genesis:
  - an import grant with read-only access, `expires` not after `issued`, or a `server` member;
  - `importedFrom` that isn't 32 lowercase hex.

**Outcomes.** Inside an authority envelope, any failure while verifying an attached signature
is `badSignature`, whatever check failed (`clientData` parsing including duplicate names, type,
challenge, origin, RP hash, flags, DER, ECDSA). Implementations MAY expose the failed check as a
diagnostic. Structural failures of the record itself, COSE parsing at registration, and §6.2
transition violations are `malformed`. Every other refuse case is `malformed` unless stated
otherwise.

The Swift implementation (Marginalia `packages/Colophon`, `KeyringTests.swift`) is the
behavioral reference for WebAuthn checks and recovery rules. Its bytes differ, so it's not a
byte oracle.

## 11. Decisions on the draft-1 open questions

| Question | Decision |
| --- | --- |
| Custody and presence as signed fields | Left out of 0.4. They're host-side display until attestation exists, and can be added later as a new optional field. |
| Layout threshold | Control rule (§6.3), with UV |
| Refuse single-key keyrings | No. Hosts warn based on actual surviving quorums and openable slots (§4.2). |
| High-S | Accepted, with normalization only inside verification (§3.3) |
| Old library ID on the copy | Optional `importedFrom` on genesis, display only (§9) |

## 12. Review log

| Date | Reviewer | Findings | Resolution |
| --- | --- | --- | --- |
| 2026-11-08 | Codex (read-only) | 17: 8 high, 9 medium | All adopted. Genesis circularity was solved by dropping the library ID from slot info, rather than deferring slots. |
| 2026-11-08 | agy (read-only) | 17 or more: 3 critical, 6 high, the rest medium and low | All adopted, including verification order, canonical omission, strict slot shapes, the `p256` low-S note and the import grant. |

| 2026-11-08 | Codex round 2 | 2 of 34 round-1 items still open (historical vault freshness; error codes); 8 new findings | All adopted: per-principal key uniqueness, slot preservation, `null` scope, closed field sets with authorized `newerFormat`, import expiry semantics, PRF construction from an assertion, multiset comparison, vectors before freeze |
| 2026-11-08 | agy round 2 | 11 new findings | All adopted. Threshold ordering is resolved the other way from Swift: `recoverThreshold > threshold` is explicitly allowed. A deterministic PRF salt was declined in favor of the assertion-based construction. |

The reviews are kept beside this file as `colophon-0.4-keys-review-*.md`. Both round-2 reviews
say the spec is ready to freeze once their findings are fixed and the §10 vectors are
published. The vectors come from implementation work package W4.
