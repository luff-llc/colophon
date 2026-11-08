# Colophon 0.4 (draft): keys and the keyring

**Status: S2 specification draft for review, 2026-11-08.** Not implemented. When it's accepted,
this text is folded into `colophon-0.4.md`. It replaces Colophon 0.3 §2 (private-key steps),
§3 (who epochs are sealed to) and §4 (authority), and leaves operations, modules and HTTP
exchange (§5–§8) as they are. Requirements and rationale:
[Galley F2](https://github.com/luff-llc/galley/blob/main/docs/foundations/f2-keys.md) (private).

MUST, SHOULD and MAY express protocol requirements. Every MUST has a conformance vector in
`conformance/0.4/keys/` (§10).

## 1. What changes from 0.3, and why

| Change | Reason |
| --- | --- |
| A **keyring of controllers** replaces the single root and the recovery identity. Controllers are passkeys, security keys, device owner keys or recovery kits, with roles and thresholds. | No single device or key is the library. Losing any one key doesn't lose the library. |
| Signatures come in two **forms**: `raw` P-256 and `webauthn` assertions. Records can carry **cosignatures**. | Passkeys can't sign arbitrary bytes. Thresholds need several signatures over one body. |
| A **vault** identity receives every epoch, in place of root and recovery. Its seed is opened through **slots**: sealed, PRF or combined. | Controllers can change without resharing every epoch to each of them. A passkey can unlock data through PRF. |
| `reshare`, `handover` and `recover` are removed. One `keyring` entry covers every authority change. | One verified rule for every change, instead of three special cases. |
| Agents and servers can **never** be controllers. | Agents work inside grants; they never hold authority. |
| No 0.1 or 0.3 authority record is interpreted. Older libraries become 0.4 libraries by **clean copy** (§9). | No migration code paths in the verifier. |

These are unchanged: member identities, requests, grants, member kinds, epochs and HPKE,
operations, live state, layout, and canonical bytes. The protocol marker for authority bodies
becomes `colophon/authority/4`. The marker for operations stays `/3`.

## 2. Keys

### 2.1 Key descriptor

```json
{"form":"raw","signing":"<base64>","agreement":"<base64>"}
{"form":"webauthn","signing":"<base64>","rp":"id.luff.works","credential":"<base64>"}
```

| Field | Rule |
| --- | --- |
| `form` | `raw` or `webauthn`. An unknown value MUST fail with `newerFormat`. |
| `signing` | An uncompressed 65-byte P-256 point. For `webauthn`, it's converted from the credential's COSE_Key at registration (§2.3). |
| `agreement` | `raw` only, and optional. An uncompressed P-256 point, required when a `sealed` slot is sealed to this key. `webauthn` keys MUST NOT have one. |
| `rp` | `webauthn` only, and required. The relying party ID. |
| `credential` | `webauthn` only, and required. The credential ID, used as a lookup hint. It MUST NOT affect verification. |

The **key ID** is the first 32 lowercase hex characters of SHA-256 of the `signing` bytes,
the same scheme as member IDs.

### 2.2 Private-key work stays in the host

The core holds no platform private key. Every signature and ECDH is two-phase (0.3 §2):
`begin_*` returns the exact bytes or challenge, and `finish_*` verifies the result before
accepting it. The **vault seed** is a library secret, not a platform key. The core MAY hold it
in memory for the length of a session. The core MUST NOT persist it. The host persists it only
inside a slot.

### 2.3 COSE parsing (registration)

A WebAuthn registration's COSE_Key MUST be a definite-length CBOR map with:

- `kty` (1) = 2 (EC2);
- `alg` (3) = −7 (ES256);
- `crv` (−1) = 1 (P-256);
- `x` (−2) and `y` (−3) as 32-byte strings.

The key is `0x04 ‖ x ‖ y`. Any other shape, or an invalid point, MUST be rejected with
`malformed`. Attestation MAY be recorded and MUST NOT be required.

## 3. Signatures

### 3.1 Envelope

```json
{"body":"<base64>","signature":"<base64>",
 "assertion":{"authenticatorData":"<base64>","clientData":"<base64>"},
 "cosignatures":[{"signer":"<keyID>","signature":"<base64>","assertion":{...}}]}
```

`assertion` and `cosignatures` are present only when used, so records that don't use them
keep 0.3's shape. The primary signer is the body's `by`. Every cosignature signs the **same
body bytes**. A primary signer and its cosigners MUST be distinct key IDs, and each MUST be a
controller in the keyring that authorizes the entry (§6.3).

### 3.2 Verifying a `raw` signature

`signature` is 64 bytes, `r ‖ s`. It's ECDSA P-256 with SHA-256 over the exact `body` bytes.
`assertion` MUST be absent.

### 3.3 Verifying a `webauthn` signature

`assertion` MUST be present. A verifier MUST check all of the following, in order:

1. `clientData` parses as a JSON object with:
   - `type` equal to `"webauthn.get"`;
   - `challenge` equal to the unpadded base64url of SHA-256(`body`);
   - `origin` equal to `https://<rp>` or `https://<label>.<rp>`;
   - `crossOrigin` absent or `false`.

   Other members are ignored.
2. `authenticatorData` is at least 37 bytes, and bytes 0–31 equal SHA-256 of the UTF-8 `rp`.
3. The flags byte (32) has UP (`0x01`) set. UV (`0x04`) MUST be set when the controller's
   `verification` is `true`, and for every signature on a `keyring` or `genesis` entry.
4. The sign counter (bytes 33–36) is ignored, because synced passkeys report zero.
5. `signature` is ASN.1 DER ECDSA P-256 over `authenticatorData ‖ SHA-256(clientData)`. A
   verifier MUST accept only DER that is minimally encoded, with r and s in [1, n−1]. High-S
   values are accepted, because authenticators produce them.

The DER bytes are kept exactly as received. Raw `r ‖ s` applies only to `raw` signatures.

## 4. Controllers and the keyring

### 4.1 Controller

```json
{"key":{...descriptor...},"label":"Passkey","roles":["approve","recover"],"verification":true}
```

| Field | Rule |
| --- | --- |
| `roles` | A non-empty subset of `control`, `approve` and `recover`. An unknown role MUST fail with `newerFormat`. |
| `verification` | Optional, `webauthn` only. Require UV on every signature by this controller. |
| `label` | Display only. |

The controller ID is the key ID. A controller key MUST NOT be the signing key of a member whose
authenticated kind is `agent` or `server`. An entry that would make one a controller is invalid,
and so is a grant that admits a controller's key as an agent or server.

### 4.2 Keyring

```json
{"controllers":[...],"threshold":1,"recoverThreshold":1,"vault":{"signing":"…","agreement":"…"},"slots":[...]}
```

- `controllers` is sorted by ID, with no duplicate IDs.
- `threshold` is between 1 and the number of `control` controllers.
- `recoverThreshold` is between 1 and the number of `recover` controllers, or 0 when there
  are none.
- At least one `control` controller MUST exist.
- `vault` is the vault's public identity (§5.1).
- Every slot names existing controllers.

A keyring with fewer than two controllers holding `recover` or `control` is valid, but hosts
SHOULD warn that losing one key loses the library.

## 5. Vault and slots

### 5.1 Vault

The vault seed is 32 random bytes. Its identity is derived with the 0.3 §2 software-identity
procedure, using HKDF salt `colophon/vault/4`. **Every epoch MUST be sealed to exactly the vault
and the active, unexpired members with read access to that namespace.** That replaces 0.3's
"root, recovery and members". The vault's recipient ID in HPKE `info` is its key ID.

### 5.2 Slots

Every slot has `kind`, `controllers` (the IDs whose keys open it, in order), and `label`.
The common info string is
`I = "colophon/vault-slot/4\n" ‖ libraryID ‖ "\n" ‖ vaultID ‖ "\n" ‖ kind ‖ "\n" ‖ join(controllers, ",")`.

| Kind | Fields | Opening |
| --- | --- | --- |
| `sealed` | `sealed` (an HPKE sealed key, as 0.3 §3) | The single controller's `raw` key with `agreement` opens it. HPKE `info` and AAD are `I`. The plaintext is the 32-byte seed. |
| `prf` | `salt` (32 bytes), `box` | The single controller is `webauthn`. The host evaluates PRF with `salt` during an assertion. The key is HKDF-SHA256(IKM = PRF output, salt = `salt`, info = `I`, 32 bytes). `box` is AES-256-GCM `nonce(12) ‖ ciphertext ‖ tag`, with AAD `I`, and its plaintext is the seed. |
| `combined` | `parts`, `box` | Each part is `{"kind":"sealed","sealed":…}` or `{"kind":"prf","salt":…}`, in `controllers` order. Each part yields a 32-byte secret: the HPKE plaintext, or the HKDF output as above. The key is HKDF-SHA256(IKM = the secrets concatenated in order, salt = empty, info = `I`, 32 bytes). `box` is as for `prf`. |

A wrong secret MUST fail with `vaultLocked`. A slot whose `controllers` aren't current
controllers is invalid.

## 6. Authority

### 6.1 Body

Each authority body contains:

- `protocol: "colophon/authority/4"`;
- contiguous `seq` from 1;
- `previous`: SHA-256 of the exact preceding body, null only at genesis;
- `issued`;
- `by`: the primary signer's controller ID;
- `kind`, and that kind's fields.

The library ID is the first 32 hex characters of SHA-256 of the exact genesis body.

### 6.2 Kinds

| Kind | Fields | Effect |
| --- | --- | --- |
| `genesis` | `label`, `namespaces`, `keyring` | Creates the library and its first keyring. The initial epochs follow in a `rekey`. |
| `rekey` | `epochs` | Introduces consecutive epochs, sealed per §5.1 |
| `grant` | `request`, `grant`, `shares` | As 0.3 |
| `revoke` | `memberID`, `kept`, `epochs` | As 0.3, with epochs sealed per §5.1 |
| `keyring` | `keyring`, and also `shares` and `epochs` when the vault changes | Replaces the keyring wholesale. If `keyring.vault` differs from the current vault, `shares` MUST seal every existing epoch to the new vault, and `epochs` MUST start a new epoch in every namespace sealed per §5.1. The old vault receives nothing new. |
| `layout` | `layout` | As 0.3. Never lowers the layout. |

### 6.3 Who may sign what

All signers are evaluated against the keyring **before** the entry, except for `genesis`,
which is evaluated against its own new keyring.

| Kind | Required signatures |
| --- | --- |
| `genesis` | Distinct `control` controllers of the new keyring, at least its `threshold`. UV is required on WebAuthn signatures. |
| `rekey`, `grant`, `revoke` | One controller with `approve`. A controller with `control` but not `approve` may sign `rekey`. |
| `layout` | One controller with `control` |
| `keyring`, by control | Distinct current `control` controllers, at least the current `threshold`. UV is required. |
| `keyring`, by recovery | Distinct current `recover` controllers, at least the current `recoverThreshold`, with UV required. Valid **only if the change only adds**: every current controller is unchanged, with the same key, roles and verification; `threshold`, `recoverThreshold`, `vault` and every current slot are unchanged; and only new controllers and new slots for them are added. |

The verifier tries the control rule first. If that fails, it tries the recovery rule, and if
both fail the entry is refused with `badSignature`. An unknown kind or field MUST stop replay
with `newerFormat`, before any content is read.

### 6.4 Removing a controller

Removing a controller, or taking a role away from one, MUST rotate the vault (§6.2). It's
authorized only by the control rule. The removed controller's slots MUST be absent from the
new keyring.

## 7. Members

Requests, grants, member kinds, the pairing code, expiry and write budgets work as in 0.3 §4.
Grants are signed by an `approve` controller rather than the root. Later foundation work
(Galley F3) extends grant restrictions. That extension is out of scope here.

## 8. Host interface (normative behavior, informative names)

- **Prepare an authority change:** the core returns the exact body and the signers that
  satisfy §6.3 among the keys the host says it has. For WebAuthn signers it also returns the
  challenge, SHA-256(body).
- **Finish the change:** the host supplies signatures and assertions. The core verifies each
  one against §3, then checks §6.3, then returns the record. Nothing is written if any check
  fails.
- **Open the vault:** the core lists the slots the host's available keys can open, with each
  one's PRF salts and HPKE `enc` values. The host returns PRF outputs and raw ECDH secrets. The
  core opens the slot and keeps the seed for the session.
- **One prompt per action:** the core returns every body that one action needs before asking
  for any signature, so the host can collect all of them in one ceremony per key.

## 9. Clean copy from older libraries

A 0.4 verifier never reads 0.1 or 0.3 authority. Instead, a **copy tool**:

1. Reads the old library **read-only**, with that version's own verifier, as an existing
   member with read access. The old root isn't required, because the copy doesn't claim to
   be the same library.
2. Creates a **new** 0.4 library: a new library ID, a keyring the person sets up (at least a
   device owner key, normally also a passkey and a recovery kit), and the same namespaces.
3. Imports operations through the existing import contract (`imports.rs`). Each copied
   operation is re-signed by the copying member and carries `imported:
   {"library": <old ID>, "signedBodyDigest": <exact old body digest>}`.
4. Reports counts per namespace, plus every record it couldn't copy and why. The old library
   is never written. The person decides when to stop using it.

Grants, members and agents are **not** copied. They're approved again in the new library.

## 10. Conformance

Every case below is generated from published software keys and a synthetic WebAuthn
authenticator (fixed P-256 key; `authenticatorData = SHA-256(rp) ‖ flags ‖ 00000000`).

**Accept cases:**

- Genesis with one raw controller.
- Genesis with threshold 2.
- A passkey grant.
- Rekey by a control-only controller.
- A recovery that only adds.
- A controller removal with vault rotation and history readable by the new vault.
- A combined slot opened with both parts.
- A PRF slot opened.

**Refuse cases, each with its expected outcome:**

- WebAuthn: wrong challenge; wrong RP hash; foreign origin; `crossOrigin: true`;
  `webauthn.create`; UP missing; UV missing where required; non-minimal DER; another
  controller's key.
- Threshold not met.
- Recovery that removes, demotes, changes a threshold or changes the vault.
- Removal without rotation.
- An agent key as a controller.
- A duplicate cosigner.
- A slot naming a non-controller.
- A wrong PRF output.
- Unknown form, role or slot kind, each with `newerFormat`.
- A 0.3 authority body, with `newerFormat` or `malformed`, never interpreted.

The Swift implementation (Marginalia `packages/Colophon`, `KeyringTests.swift`) is the behavioral
reference for §3.3 and §6.3. Its bytes differ (0.1 markers), so it's not a byte oracle.

## 11. Open questions for review

1. Should `custody` and `presence` be signed controller fields, or kept host-side display only?
   (Galley F2 question 2.) This draft leaves them out.
2. Should `layout` require the control threshold rather than one signature?
3. Should a keyring with only one `recover`-or-`control` key be refused, rather than warned
   about?
4. Is high-S tolerance for WebAuthn DER acceptable? (Some verifiers require low-S.)
5. Should the copy tool keep the old library ID as `importedFrom` on the genesis, for display
   only?
