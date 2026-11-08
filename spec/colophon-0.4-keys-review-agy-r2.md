### 1. Round-1 Findings Status

**Codex Round-1 Findings**
1. **Codex #1 (Recovery manufacturing a control quorum):** RESOLVED — §6.3 now requires every recovery-added controller to have roles `["approve"]` when `recoverThreshold < threshold`.
2. **Codex #2 (Zero recovery threshold not explicitly disabled):** RESOLVED — §6.3 explicitly requires `recoverThreshold > 0` for the recovery rule to apply.
3. **Codex #3 (Empty/one-part/duplicate combined slot):** RESOLVED — §5.2 now requires at least 2 distinct controllers and matching `parts` length and order.
4. **Codex #4 (Sealed combined parts need independent secrets):** RESOLVED — §5.2 now mandates that each sealed part encrypt a fresh, independent random 32-byte secret, never the seed or a reused secret.
5. **Codex #5 (Historical vault reuse `A → B → A`):** RESOLVED — §2.3 and §6.2 now require every new vault to be fresh across the library's entire history.
6. **Codex #6 (Genesis slot circularity with `libraryID`):** RESOLVED — §5.2 removed `libraryID` from `I` and `Ii`, binding slot info to `vaultID` instead.
7. **Codex #7 (Single minority controller raising `layout`):** RESOLVED — §6.3 now requires the control rule (threshold + UV) for `layout`.
8. **Codex #8 (Android native origins and multi-label subdomains):** RESOLVED — §2.2 adds `origins` on `webauthn` descriptors and §3.3 specifies multi-label subdomain and allowlisted origin matching.
9. **Codex #9 (Controller authority vs content membership separation):** RESOLVED — §1, §2.3, and §7 separate controllers, members, and vaults completely and remove implicit genesis membership.
10. **Codex #10 (One WebAuthn ceremony cannot sign multiple bodies or precede PRF/unlock):** RESOLVED — §8 now sequences unlock first, new PRF evaluation before building the body, and one WebAuthn assertion per distinct body.
11. **Codex #11 (Portable PRF bytes and CTAP `hmac-secret` transformation):** RESOLVED — §5.2 specifies exact WebAuthn PRF input/output and the `"WebAuthn PRF" ‖ 0x00 ‖ salt` CTAP transformation.
12. **Codex #12 (Binding decrypted slot plaintext to `keyring.vault`):** RESOLVED — §5.1 requires checking 32-byte length, deriving the identity, and matching both public keys against `keyring.vault`.
13. **Codex #13 (§3.1 envelope rules applying to requests and operations):** RESOLVED — §3 explicitly scopes `assertion` and `cosignatures` to `colophon/authority/4` and marks them `malformed` on requests and operations.
14. **Codex #14 (Clean copy contradicting 0.3 §7.2 `colophon.importBatch`):** RESOLVED — §7 and §9 replace root-only import with a control-authorized expiring `grant.import` and use `colophon.importBatch`.
15. **Codex #15 ("Every epoch" conflicting with immutable historical seals):** RESOLVED — §5.1 scopes the exact recipient rule to each newly introduced epoch at its introducing entry.
16. **Codex #16 (Explicit outer SHA-256 hash in WebAuthn step 5):** RESOLVED — §3.3 step 5 explicitly defines `M = authenticatorData ‖ SHA-256(clientData bytes)` and verifies ES256 over `SHA-256(M)`.
17. **Codex #17 (Duplicate-key JSON and CBOR map parsing):** RESOLVED — §2.1 and §2.5 mandate rejecting duplicate JSON member names at any depth and duplicate/extra CBOR keys.

**agy Round-1 Findings**
1. **agy #1 (Recovery escalating from lower `recoverThreshold` to `control`):** NOT RESOLVED — §6.3 fixes dynamic recovery additions when `recoverThreshold < threshold`, but §4.2 still allows a keyring with `recoverThreshold > 1` and `recoverThreshold < threshold` (which Swift's `KeyringRules.thresholdFault` rejects) or `recoverThreshold == threshold` where `recover`-only keys can manufacture `control` keys without holding `control`.
2. **agy #2 (Controller removal/demotion without vault rotation and historical vault reuse):** RESOLVED — §6.2 requires vault freshness and requires rotation on controller removal or role loss while clarifying demoted controller slots.
3. **agy #3 (Principal key reuse across controllers, members, and vaults):** RESOLVED — §2.3 enforces strict "one key, one principal" across signing and agreement keys throughout history.
4. **agy #4 (`combined` slot part domain separation and part count):** RESOLVED — §5.2 defines distinct per-part info `Ii = "colophon/vault-part/4\n" ...` and requires at least 2 distinct controllers.
5. **agy #5 (Genesis slot info circularity with `libraryID`):** RESOLVED — §5.2 drops `libraryID` from `I` and `Ii`.
6. **agy #6 (Two-phase host cannot evaluate new PRF slot and sign body in one WebAuthn prompt):** RESOLVED — §8 step 2 and step 5 explicitly separate new-slot PRF evaluation from body signing.
7. **agy #7 (Vault rotation with passkey cannot unlock old vault and sign `keyring` in one ceremony):** RESOLVED — §8 step 1 requires unlocking the vault into the session before preparing epoch-reading/sealing entries.
8. **agy #8 (WebAuthn origin matching and `rp` format validation):** RESOLVED — §2.2 validates `rp` syntax and §3.3 specifies exact host/subdomain character and dot rules.
9. **agy #9 (Wiring mandatory rotation on removal/demotion into verification):** PARTIALLY RESOLVED (NOT RESOLVED on `verification` downgrade) — §6.2 wires controller removal and role loss into rotation, but explicitly allows lowering `verification: true` to absent without rotating the vault, and does not state the error code (`malformed`) when rotation is omitted.
10. **agy #10 (`colophon.importBatch` broken without `root` and implicit genesis member):** RESOLVED — §7 defines `grant.import` to replace the 0.3 root import role and states genesis creates no member.
11. **agy #11 (Clean copy `imported` field undefined in 0.3):** RESOLVED — §9 drops the undefined per-operation `imported` field and uses `colophon.importBatch` encrypted evidence under 0.3 §7.2.
12. **agy #12 (`seq: 2` initial `rekey` requirement):** RESOLVED — §6.2 mandates that `seq: 2` MUST be a `rekey` introducing epoch 1 for every declared namespace.
13. **agy #13 (Canonical representation of `recoverThreshold`, `verification`, `shares`, `epochs`, `cosignatures`):** RESOLVED — §2.1, §3.1, §4.1, §4.2, and §6.2 specify exact presence/omission rules for all five fields.
14. **agy #14 (COSE_Key CBOR strictness and Rust `p256` low-S normalization):** RESOLVED — §2.5 specifies exact 5-entry minimal CBOR and §3.3 step 5 specifies in-memory `min(s, n−s)` normalization.
15. **agy #15 (Verification order between `badSignature` and `newerFormat`):** NOT RESOLVED — §6.3 requires authenticating every signature before checking unknown `kind`, `form`, `role`, or `slot.kind`, which fails when an authenticated `keyring` entry adds a new controller with an unknown `form`/`role` that is then used to sign or cosign subsequent entries, or when the entry's JSON cannot be typed-parsed before signature verification.
16. **agy #16 (Slot structural validation rules and `roles` sorting/uniqueness):** RESOLVED — §4.1 and §5.2 specify `roles` sorting/uniqueness and exact slot/part shapes and byte lengths.
17. **agy #17 (`cosignatures` on single-rule entries and strict signer role checking):** RESOLVED — §3.1 and §6.3 forbid `cosignatures` on single-rule entries and require every attached signer to verify and hold the rule's role.

---

### 2. New Findings in Draft 2

#### 1. High — §5.2, §8: WebAuthn PRF evaluation during `navigator.credentials.create()` is unsupported or fails to return `prf.results.first` on Safari/iOS/macOS and Chrome with hardware security keys
- **Section:** §5.2 ("PRF bytes"), §8 step 2 ("New PRF slots need PRF before the body")
- **Problem:** §8 step 2 states: *"To create a `prf` slot or part, the host evaluates PRF for the new salt, by registering with the PRF extension or by asserting, before the core builds the entry."* And §5.2 requires: *"Before a slot is published, the host MUST confirm it opens."* On Apple platforms (iOS/iPadOS 18+, macOS 15+ `ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest` and WebKit `navigator.credentials.create`) and on Chromium when registering CTAP2 `hmac-secret` hardware security keys, evaluating PRF with input salts during **registration** (`create`) is either not exposed in the native API or returns only `{ enabled: true }` without `results.first` (because CTAP2 `authenticatorMakeCredential` only negotiates `hmac-secret: true` and does not evaluate `hmac-secret` salts until `authenticatorGetAssertion`). Furthermore, even if a platform returns `results.first` on `create`, confirming the slot opens via `get` or signing the resulting `genesis`/`keyring` body requires a separate assertion ceremony. Worse, if a host generates a random `salt` per slot at registration time, it must perform: (1) WebAuthn registration (`create`), (2) a first WebAuthn assertion (`get`) with `salt` to obtain `P` and build the `prf` slot's `box` inside `body`, and (3) a second WebAuthn assertion (`get`) to sign `challenge = SHA-256(body)`—three consecutive biometric prompts just to create or add a passkey controller!
- **Concrete failure scenario:** An iOS or web host implements passkey enrollment by passing `prf: { eval: { first: salt } }` to `navigator.credentials.create()` as suggested by §8 step 2. On Safari/iOS and on Chrome with a YubiKey, `results.first` is `undefined` after registration (`enabled: true` only), so enrollment always fails under §5.2 (*"If PRF is unsupported or returns no result, that MUST fail explicitly"*). If the host instead runs `get` to evaluate the random `salt` and then runs `get` again to sign `body`, the user is hit with 3 consecutive Face ID / security key touches, which Safari/WebKit blocks after the user-gesture activation window expires on the first `await`.
- **Proposed spec wording:** In §5.2 and §8 step 2, add:
  > "Because WebAuthn authenticators and platform APIs (including iOS `AuthenticationServices` and CTAP2 `hmac-secret` security keys) commonly report only `prf.enabled` during registration without evaluating `prf.results.first`, hosts MUST NOT rely on registration returning a PRF output. To avoid three consecutive prompts when enrolling a passkey that will both open a `prf` slot and sign the authority entry, a host MAY either: (a) sign the authority entry with an already-present controller key after a single post-registration PRF assertion, or (b) derive the slot's `salt` deterministically (e.g., `SHA-256("colophon/prf-salt/4\n" ‖ rp)`), evaluate that fixed salt in the first post-registration assertion to obtain `P` in session memory, and then sign `body` in the second assertion (confirming `P` on the same salt in the same assertion)."

---

#### 2. High — §2.2, §6.2: Key ID collision check vs "One key, one principal" (§2.3) has a gap between key ID (32-hex truncated SHA-256 of `signing`) and full public keys (`signing` and `agreement`)
- **Section:** §2.2, §2.3, §4.1, §4.2, §5.1, §6.2
- **Problem:** §2.2 defines Key ID as `first 32 lowercase hex characters of SHA-256(signing)`. §2.3 states: *"A key (by signing key or agreement key) MUST NOT appear as more than one of these across the library's whole history: a controller key; a member identity; a current or past vault identity."* However:
  1. Within a single principal (e.g., a `raw` controller with `agreement`, a member `PublicIdentity`, or a `vault` `PublicIdentity`), §2.2 and 0.3 §2 never forbid `signing == agreement` (using the exact same 65-byte P-256 point for both ECDSA signing and ECDH key agreement on the same principal)! Using the same P-256 key pair for ECDSA and raw ECDH in the host violates cryptographic key separation and is impossible on WebCrypto, Android Keystore, and iOS Secure Enclave (which enforce single-usage keys: `ECDSA` vs `ECDH`).
  2. Can two *different* controllers in the same keyring (or across history) share the same `agreement` key while having different `signing` keys? §4.2 only checks that `controllers` has no duplicate controller IDs (`signing` key IDs), and §2.3 only forbids a key from appearing across *different* principal categories ("more than one of these: a controller key; a member identity; a current or past vault identity"), not across two distinct controllers or two distinct members! If Controller A and Controller B share the same `agreement` key, removing Controller A and rotating the vault while sealing a `sealed` slot to Controller B leaves the new vault decryptable by Controller A's agreement key!
  3. §2.3 does not explicitly require checking historical **key IDs** (`id`) in addition to full 65-byte points (`signing` and `agreement`), nor does it forbid a member's `signing` key from matching another member's `agreement` key.
- **Concrete failure scenario:** A library has two `raw` controllers `C1` and `C2` that have distinct `signing` keys (`id(C1) != id(C2)`) but were registered with the same `agreement` public key `K_agree`. Both are controllers ("a controller key" in §2.3), so §2.3 is satisfied. Later, `C1` is compromised and removed via a `keyring` entry that rotates the vault and creates a `sealed` slot for `C2` (which encrypts the new vault seed to `C2.agreement == K_agree`). Because `C1` holds the private key for `K_agree`, the removed controller `C1` can decrypt `C2`'s slot and compromise the rotated vault!
- **Proposed spec wording:** Replace §2.3 with:
  > "Across the library's entire history (every current or past controller, every admitted member, and every current or past vault), every 65-byte P-256 public point (`signing` or `agreement`) and every 32-hex key ID MUST belong to at most one principal and one key usage (`signing` vs `agreement`). Specifically:
  > 1. Within any controller, member, or vault, `signing` and `agreement` MUST be distinct points.
  > 2. No two controllers (concurrent or historical), no two members, and no two vaults MAY share a `signing` point, an `agreement` point, or a key ID, nor MAY any principal's `signing` point equal any principal's `agreement` point.
  > 3. Only `keyring` entries that retain an existing controller or the unchanged current `vault` MAY repeat that existing principal's keys. Any other collision is `malformed`."

---

#### 3. High — §6.3, §4.2: Recovery rule allows `recover`-only controllers to manufacture `control` keys and seize the library when `recoverThreshold == threshold`
- **Section:** §4.2, §6.3 ("Recovery rule")
- **Problem:** In §6.3, the recovery rule restricts added controllers to `["approve"]` **only** when `recoverThreshold < threshold`:
  > *"If `recoverThreshold < threshold`, every added controller MUST have roles exactly `["approve"]`."*
  Look at what happens in the standard case where `threshold: 1` and `recoverThreshold: 1` (the exact example in §4.2: `{"controllers":[...],"threshold":1,"recoverThreshold":1,...}`), where Controller 1 is the user's passkey (`roles: ["control", "approve"]`) and Controller 2 is an offline recovery key (`roles: ["recover"]`, without `"control"`). Here `recoverThreshold == threshold` (`1 == 1`). If the recovery rule is supposed to allow `recover` controllers to recover `control` when `recoverThreshold >= threshold`, why does the recovery rule forbid rotating the vault or removing lost controllers directly, forcing a two-step dance where `recover` first adds a new `control` key (without rotating the vault or touching existing controllers) and then that new `control` key signs a second `keyring` entry under the control rule to remove the old controllers and rotate the vault?
  More critically: what if `threshold: 1` and `recoverThreshold: 2` (`recoverThreshold > threshold`)? Under §4.2, `recoverThreshold` is constrained only by `1 ..= count(recover)` and `threshold` by `1 ..= count(control)`, so `recoverThreshold > threshold` is valid in 0.4 even though Swift (`KeyringRules.thresholdFault`, line 134: `if required > 1, threshold < required || control < threshold { return .threshold }`) **rejects** `threshold < recoverThreshold` as `.malformed("keyring threshold")`!
- **Concrete failure scenario:** A Swift client and a Rust client both validate a keyring with 1 `control` controller (`threshold: 1`) and 2 `recover` controllers (`recoverThreshold: 2`). The Rust client accepts it under §4.2 (`threshold` in `1..=1`, `recoverThreshold` in `1..=2`); the Swift reference (`Keyring.swift` line 134) rejects it as `malformed("keyring threshold")` because `recoverThreshold > 1 && threshold < recoverThreshold`. The library is permanently split-brained between Swift and Rust.
- **Proposed spec wording:** Either:
  1. Align §4.2 with `Keyring.swift` line 134 by adding: *"When `recoverThreshold > 1`, `threshold` MUST be at least `recoverThreshold`."* OR
  2. Explicitly state in §4.2 and §10 that `recoverThreshold > threshold` is permitted in 0.4 (unlike the Swift 0.1 reference) and add a conformance accept vector for `threshold: 1, recoverThreshold: 2`.

---

#### 4. High — §6.3: Verification order (`badSignature` before `newerFormat`) is underspecified when the entry body contains unknown `form`, `role`, `slot.kind`, or `kind`
- **Section:** §2.1, §3.1, §6.3 ("Verification order")
- **Problem:** §6.3 specifies:
  > *"For seq > 1, the verifier MUST:
  > 1. check structure, size and §2.1;
  > 2. authenticate every signature against the prior keyring;
  > 3. then reject an unknown `kind`, `form`, role or slot kind with `newerFormat`."*
  Look closely at how Step 1, Step 2, and Step 3 interact for `seq > 1`:
  1. **Which signature rule applies in Step 2 when `entry.kind` is unknown (e.g. `"kind": "delegate"`)?** In §6.3, whether an entry requires the **Control rule** (with UV and `threshold` signers, cosignatures allowed) or the **Single rule** (`approve` signer, no cosignatures, UV not required unless `controller.verification == true`) depends on `entry.kind`! If `entry.kind` is an unknown future kind `"delegate"`, which rule does Step 2 use to "authenticate every signature against the prior keyring" before Step 3 returns `newerFormat`? One implementer will require the Control rule for unknown kinds; another will accept any valid signature from `by` (and any `cosignatures`) by a controller in the prior keyring; a third will reject cosignatures on unknown kinds!
  2. **What is "check structure, size and §2.1" in Step 1 for an unknown `kind`, `form`, or `slot.kind`?** Under §2.1, *"Fields of the wrong type, and fields this document forbids, MUST be rejected before any authorization decision."* If a future `kind: "delegate"` has a field `"delegatee": "..."`, or a future slot `kind: "passcode"` has a field `"iterations": 100000`, a strict typed parser in Step 1 will reject `"delegatee"` or `"iterations"` as a forbidden/unknown field (`malformed`) **before** Step 2 or Step 3 is ever reached—making `newerFormat` unreachable for any future `kind`, `form`, or `slot.kind` that carries its own fields!
- **Concrete failure scenario:** A newer client writes an authenticated authority entry at `seq: 4` with `"kind": "stewards", "stewards": [...]` (or a `keyring` entry with a new slot `"kind": " backup", " backupData": "..."`), signed by the control quorum. An older 0.4 verifier runs Step 1 ("Fields this document forbids MUST be rejected before any authorization decision") and rejects the entry as `malformed` instead of `newerFormat`, or fails to know whether Step 2 requires the Control rule or Single rule for `"kind": "stewards"`.
- **Proposed spec wording:** Clarify §6.3 "Verification order":
  > "For `seq > 1`, the verifier MUST:
  > 1. Parse the outer envelope (§3.1) and verify that `body` is valid UTF-8 JSON with no duplicate keys (§2.1) and valid common header fields (`protocol == "colophon/authority/4"`, `seq == latest + 1`, `previous == lastDigest`, valid `issued`, and `by` naming a controller in the prior keyring).
  > 2. Verify that `by` and every signer in `cosignatures` is a distinct controller in the prior keyring and that every attached signature cryptographically verifies over `body` (§3.1–§3.3). If `kind` is not one of the six known kinds in §6.2, authenticating at least one valid signature (or the prior keyring's **control rule**) satisfies Step 2 and the verifier MUST then return `newerFormat` without checking action-specific fields.
  > 3. For a known `kind`, if `kind == "keyring"` and any controller or slot in the proposed `keyring` has an unknown `form`, `role`, `slot.kind`, or `part.kind`, verify that the prior keyring's control or recovery signers and thresholds are satisfied (ignoring unknown fields on unknown `form`/`slot.kind`/`part.kind` objects), and then return `newerFormat`.
  > 4. Otherwise, enforce strict schema validation (§2.1) on all fields of the known `kind`, `form`, and `slot.kind`, and enforce the authorization and transition rules of §6.2–§6.3."

---

#### 5. Medium — §6.2, §6.3: Lowering `verification: true` to absent on a WebAuthn controller does not require vault rotation and has no conformance vector
- **Section:** §6.2 ("Rotation is required..."), §6.3
- **Problem:** §6.2 states:
  > *"Rotation is required when a controller present before the entry is absent after it, or loses any role. ... Lowering `verification` doesn't by itself require rotation, but it is a control-rule change."*
  And what if a `keyring` entry changes an existing controller's `key` (Wait: controller ID is derived from `key.signing`, so changing `key.signing` changes the ID, which removes the old ID and adds a new ID—requiring rotation! What if a `raw` controller keeps the same `key.signing`—and therefore the **same controller ID**—but changes `key.agreement`, or removes `key.agreement`? Or what if a `webauthn` controller keeps the same `key.signing`—same controller ID—and changes `rp`, `credential`, or `origins`?)
  Look at what happens if a `raw` controller `C1` keeps the same `signing` key (so `C1`'s controller ID is present before and after the entry, with the same `roles`), and **removes or replaces `C1.key.agreement`** because `C1`'s old agreement key was compromised or rotated! Because `C1` is still present by controller ID and lost no role, §6.2 does **not** require vault rotation! Even worse, what if a `keyring` entry is signed under the **control rule** and modifies `C1.key.agreement` without rotating the vault, or what if a `webauthn` controller changes `rp` or `origins`?
- **Concrete failure scenario:** A `raw` controller's ECDH agreement key is rotated (or stripped) in a `keyring` entry while keeping its `signing` key (and thus its controller ID) and `roles` unchanged. Under §6.2, because the controller ID is still present and lost no role, the verifier does not require rotating the vault, leaving the vault seed accessible to the removed `agreement` key.
- **Proposed spec wording:** In §6.2, update the rotation trigger rule:
  > "**Rotation is required** when any controller present (by ID) before the entry is absent after it, loses any role, or removes or changes its `agreement` key. Violating this requirement is `malformed`."

---

#### 6. Medium — §5.2: Slot `label` validation, `slots` ordering/duplicates, and unused/orphan slot rules are incomplete
- **Section:** §4.1, §4.2, §5.2
- **Problem:**
  1. §4.1 specifies for a controller: `"label": 1–200 bytes. Display only.` In §5.2, *"Every slot has `kind`, `controllers` and `label`."* Neither §4.2 nor §5.2 specifies the type or byte-length constraints on `slot.label` (is empty `""` allowed, or must it also be `1–200` UTF-8 bytes?).
  2. In §5.2, the table specifies `sealed`, `prf`, and `combined` shapes in prose, not exact JSON field names and types:
     - For `sealed`: is the JSON object `{"kind":"sealed","controllers":["<id>"],"label":"...","sealed":{"enc":"<base64>","ciphertext":"<base64>"}}`? Or are `enc` and `ciphertext` top-level fields on the slot? The table says: *"`sealed` is `{enc (65-byte point), ciphertext (48 bytes)}`"*, while for `prf` it says *"`salt` (32 bytes), `box` (60 bytes)"* (top-level fields on the slot!), and for `combined` it says *"`parts` has the same length and order. `box` is 60 bytes. Part `i` is `{"kind":"sealed","sealed":…}` ... or `{"kind":"prf","salt":…}`"*.
     - Without an explicit JSON schema or example for all three slot shapes and both part shapes, one implementer will serialize a `sealed` slot with top-level `"enc"` and `"ciphertext"` (matching `prf`'s top-level `"salt"` and `"box"`), while another will nest `"sealed": {"enc": "...", "ciphertext": "..."}` (matching Swift `VaultSlot.swift` line 16 `public let sealed: SealedKey?`).
     - Similarly, in Swift `VaultSlot.swift`, a slot has `controller: String?` (singular), `recipient: PublicIdentity?`, and `credential: Data?`, whereas 0.4 §5.2 replaces all of those with `controllers: ["<keyID>", ...]` (an array of controller IDs, even for 1-controller `sealed` and `prf` slots) and omits `recipient` and `credential` from slots and parts! Because §2.1 requires rejecting any forbidden/extra field with `malformed`, the exact JSON keys of every slot and part must be unambiguous.
- **Concrete failure scenario:** Implementer A encodes a `sealed` slot as `{"controllers":["..."],"enc":"...","kind":"sealed","label":"...","ciphertext":"..."}`, while Implementer B encodes it as `{"controllers":["..."],"kind":"sealed","label":"...","sealed":{"ciphertext":"...","enc":"..."}}`. Both claim compliance with §5.2's table (`"sealed is {enc (65-byte point), ciphertext (48 bytes)}"`). Every `sealed` slot fails parsing across implementations.
- **Proposed spec wording:** Add explicit JSON examples and field tables in §5.2 for all three slot kinds and both part kinds:
  ```json
  {"kind":"sealed","controllers":["<id>"],"label":"Device","sealed":{"enc":"<base64>","ciphertext":"<base64>"}}
  {"kind":"prf","controllers":["<id>"],"label":"Passkey","salt":"<base64>","box":"<base64>"}
  {"kind":"combined","controllers":["<id1>","<id2>"],"label":"Both","parts":[{"kind":"sealed","sealed":{"enc":"<base64>","ciphertext":"<base64>"}},{"kind":"prf","salt":"<base64>"}],"box":"<base64>"}
  ```
  And specify: *"Every slot `label` is 1–200 UTF-8 bytes. Every ID in `slot.controllers` MUST exist in `keyring.controllers`. No other fields are allowed on slots or parts."*

---

#### 7. Medium — §6.2, §5.1: `keyring` vault rotation when a declared namespace has no epochs yet (or what happens if `keyring` is only at `seq > 2` vs `grant.shares` ordering)
- **Section:** §5.1, §6.2
- **Problem:** §6.2 states:
  1. *"Seq 2 MUST be a `rekey` introducing epoch 1 for every declared namespace."*
  2.What if a library only has 1 entry (`seq: 1`, `genesis`) and has not yet received `seq: 2` (`rekey`)? Does `Authority::replay` reject a 1-entry authority chain (`seq: 1` alone without `seq: 2`), or is a 1-entry chain valid until `seq: 2` is appended?
     - Look at §8 step 5 ("Prompts"): *"Hosts SHOULD design actions to need one authority body where possible. For example, creating a library with a device owner key needs presence once"* — Wait: if creating a library requires `genesis` (`seq: 1`) **and** `rekey` (`seq: 2`), that's **two** authority bodies (`authority/00000001.json` and `authority/00000002.json`)! If the creator only uses a passkey (WebAuthn controller) with `threshold: 1`, creating the library requires signing `genesis` (body 1) **and** signing `rekey` (body 2), which is **two** WebAuthn assertions (plus PRF evaluation if creating a PRF slot)! Why is initial epoch 1 in a separate `seq: 2` `rekey` entry instead of either (a) inside `genesis`, or (b) required before any content/grant? Because in 0.3, `epoch` HPKE `info` required `libraryID` (`colophon/epoch/3\n<libraryID>\n<namespace>\n<epoch>\n<recipientID>`), which is the hash of `genesis`!
  3. And because `genesis` alone does not have `seq: 2`, if a test vector in §10 ("Genesis with one raw controller", "Genesis with threshold 2 (raw plus WebAuthn)") has only `seq: 1` (`genesis`), `Authority::replay` must accept a 1-entry log (`latest == 1`), and only enforce *"Seq 2 MUST be a `rekey` introducing epoch 1 for every declared namespace"* when `seq >= 2` is present! If one implementer requires `latest >= 2` inside `Authority::replay`, the first two accept vectors in §10 ("Genesis with one raw controller" and "Genesis with threshold 2") will fail!
- **Concrete failure scenario:** Implementer A enforces *"Seq 2 MUST be a `rekey`..."* by requiring `records.len() >= 2` in `Authority::replay`. The §10 conformance vectors *"Genesis with one raw controller"* and *"Genesis with threshold 2 (raw plus WebAuthn)"* (which test `seq: 1` alone) fail on Implementer A and pass on Implementer B (who checks the rule only when `seq == 2` is replayed).
- **Proposed spec wording:** In §6.2 (`rekey`), change *"Seq 2 MUST be a `rekey` introducing epoch 1 for every declared namespace"* to:
  > "A library with only `seq: 1` (`genesis`) is valid authority with no epochs yet. If `seq: 2` is present, it MUST be a `rekey` whose `epochs` introduces epoch 1 for every namespace in `genesis.namespaces` (and no others)."

---

#### 8. Medium — §2.2, §3.3: WebAuthn `origins` allowlist validation and `rp` IPv4/syntax edge cases
- **Section:** §2.2, §3.3
- **Problem:**
  1. In §2.2, `origins` is defined as: *"`webauthn` only, and optional. A non-empty, sorted, duplicate-free list of exact additional origins, for example `android:apk-key-hash:<base64url>` (§3.3)."* It does not specify any syntax or length bounds on elements of `origins`! Can an entry in `origins` be `""` (empty string), 10 MB long, contain whitespace/newlines, or be an `http://` or `https://` URL that bypasses the `rp` check? Wait: if `origins` is only meant for native app origins (or specific additional origins), at minimum each string in `origins` must be non-empty (e.g. `1–512` ASCII bytes with no whitespace or control characters) and sorted lexicographically by UTF-8 byte order.
  2. In §2.2, `rp` is defined as: *"1–253 bytes of lowercase ASCII letters, digits, `-` and `.`, with no empty label and no leading or trailing `.`."* Under RFC 1035 / WHATWG domain rules, labels also cannot start or end with `-` (e.g. `-evil.com` or `a.-b.com`), and what about `origins` sorting order?
- **Concrete failure scenario:** One implementation validates `origins` entries as non-empty ASCII strings of `1–512` bytes (or `android:apk-key-hash:` format) while another accepts `origins: [""]` or arbitrary strings; or one sorts `origins` by UTF-16 code units (JavaScript/Swift default in some APIs) while another sorts by UTF-8 bytes.
- **Proposed spec wording:** In §2.2 (`origins`), state:
  > "`origins`: `webauthn` only, and optional. A non-empty list of 1–32 strings, sorted in strictly ascending UTF-8 byte order with no duplicates, where each string is 1–512 printable ASCII bytes (`0x21..=0x7E`)."

---

#### 9. Medium — §7, 0.3 §4: `grant.import` interaction with `request`, `access`, and `Authority::replay` vs `now`
- **Section:** §7, §6.2 (`grant`)
- **Problem:** §7 states:
  > *"`grant.import` (boolean, present only as `true`) lets that member publish `colophon.importBatch` (0.3 §7.2) in the granted namespaces. ... An import grant MUST have `expires`, MUST be signed under the control rule, and MUST NOT be given to `agent` or `server` members."*
  Three concrete questions arise between two implementers:
  1. **Does `request` also carry `import`, or is `import` granted solely by the controller in `grant`?** In 0.3 §4 (`authority.rs` line 340), `grant` checks that `grant.namespaces` is a subset of `request.namespaces` and `grant.access` is a subset of `request.access`, and `verify_request` validates the request schema. Does a `request` (`colophon/request/3`) ever contain `import`, or MUST `request` NOT contain `import` (since requests keep 0.3 format per §1 and §3), with `grant.import: true` added by the approving control quorum?
  2. **Must an import grant include `"write"` in `grant.access`?** Since `colophon.importBatch` is an operation published under `ops/<authorID>/<namespace>/...`, 0.3 §5 step 1 requires the author to have `"write"` access in `grant.access` (which in 0.3 §4 implies `"read"`). What if a `grant` has `access: ["read"]` (read-only) and `import: true`? Is a read-only import grant `malformed` at `Authority::replay`, or accepted at replay and unable to write?
  3. **Must `grant.expires` be strictly greater than `entry.issued` at `Authority::replay`?** In 0.3 (`authority.rs`), `grant.validate()` checks that `expires` is a valid timestamp, and `add_epochs` checks `!expired(&g.expires, &entry.issued)`. What if a `grant` is issued with `expires <= entry.issued` (already expired at the moment it is granted)?
- **Concrete failure scenario:** Implementer A requires `request` to also request `import: true` (or rejects `grant.import: true` when `grant.access` is `["read"]` as `malformed`), while Implementer B keeps `colophon/request/3` unchanged without `import` and allows or rejects `access: ["read"], import: true` differently.
- **Proposed spec wording:** In §7, add:
  > "`request` (`colophon/request/3`) is unchanged and never carries `import`. A `grant` with `import: true` MUST include `"write"` in `grant.access`, MUST have `expires` strictly later than the grant entry's `issued` timestamp, MUST be signed under the control rule, and MUST target a member whose `request.kind` is `device` or `app` (any violation is `malformed`, or `badSignature` if the control rule is unmet)."

---

#### 10. Low — §9, §6.2: `importedFrom` validation rules on `genesis`
- **Section:** §6.2 (`genesis`), §9 ("Clean copy from older libraries")
- **Problem:** §9 states: *"The genesis MAY carry `importedFrom: "<old library ID>"` as a signed, display-only claim. It confers nothing."* However, §6.2's `genesis` field list (`label`, `namespaces`, `keyring`) omits `importedFrom`, and §9 does not state the validation rule for `importedFrom` under §2.1 (strict parsing). Is `importedFrom` required to be exactly 32 lowercase ASCII hex characters (`[0-9a-f]{32}`), or is any non-empty string accepted? If one implementer validates `importedFrom` as 32 lowercase hex characters (matching library ID format in §6.1 and 0.3 §2) and another accepts any string or rejects `importedFrom` because it isn't listed in the §6.2 table for `genesis`, implementations will diverge.
- **Concrete failure scenario:** A `genesis` entry contains `importedFrom` with uppercase hex, a non-hex string, or valid 32-char lowercase hex. Implementer A rejects `importedFrom` because §6.2's table only lists `label`, `namespaces`, `keyring` and §2.1 forbids unlisted fields; Implementer B accepts any string; Implementer C requires 32 lowercase hex characters.
- **Proposed spec wording:** Add `importedFrom?` to the `genesis` row in §6.2's table, and in §9 specify:
  > "`importedFrom`, when present on `genesis`, MUST be 32 lowercase ASCII hex characters (`[0-9a-f]{32}`). Any other value is `malformed`."

---

#### 11. Low — §3.3 Step 5: Minimal ASN.1 DER ECDSA signature validation rules are not specified byte-for-byte
- **Section:** §3.3 step 5
- **Problem:** §3.3 step 5 says: *"`signature` MUST be strictly minimal ASN.1 DER, with `r` and `s` in [1, n−1]."* Standard crypto libraries differ subtly on edge cases of "strictly minimal ASN.1 DER": e.g., whether trailing bytes after the outer `SEQUENCE` are rejected, whether long-form length (`0x81 0x44`) is rejected when total length < 128 (a P-256 DER signature is always 68–72 bytes, so all lengths fit in 1 byte `< 0x80`), and whether leading `0x00` padding on `r` or `s` is allowed *only* when the next byte has bit `0x80` set.
- **Concrete failure scenario:** A conformance test for "non-minimal DER" (§10) uses a 2-byte length header `0x30 0x81 0x44 ...` or trailing bytes after the `SEQUENCE`, and a platform verifier whose DER parser accepts BER length encodings passes the refuse vector.
- **Proposed spec wording:** In §3.3 step 5, add:
  > "Specifically, `signature` MUST be `0x30 ‖ len ‖ 0x02 ‖ rlen ‖ r_bytes ‖ 0x02 ‖ slen ‖ s_bytes` with no trailing bytes, where `len == rlen + slen + 4` (short-form length `< 0x80`), and each of `r_bytes` and `s_bytes` is 1–33 bytes, has `0x00 <= first_byte <= 0x7f`, does not start with `0x00` unless the second byte has bit `0x80` set, and decodes big-endian to an integer in `[1, n−1]`."

---

### 3. Readiness to Freeze as v1

**Ready to freeze as `v1` once the 11 findings above are fixed.** No further architectural changes or review rounds are needed after resolving them.
