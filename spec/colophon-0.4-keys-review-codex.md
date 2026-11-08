1. **High — §6.3: recovery can manufacture a control quorum.**  
   “Only adds” permits new controllers with arbitrary roles. With `threshold: 2` and `recoverThreshold: 1`, one compromised recovery controller can add two attacker-controlled `control` keys. Those keys can then replace the entire keyring under the control rule. Swift’s `Keyring.admitsRecovery` explicitly restricts additions when recovery requires fewer signatures than control.

   **Proposed wording:** “When the current `recoverThreshold` is less than the current `threshold`, every controller added through recovery MUST have exactly the role `approve`. Such additions MUST NOT include `control` or `recover`.”

2. **High — §§4.2, 6.3: zero recovery threshold is not explicitly disabled.**  
   The draft permits `recoverThreshold: 0` when no recovery controllers exist, while authorization requires “at least” that threshold. An implementation that counts qualifying signatures can accept zero recovery signatures, allowing an approve-only primary signer to add controlling keys. Another implementation could reject this because no recovery signer exists.

   **Proposed wording:** “A `recoverThreshold` of zero disables recovery authorization. The recovery rule MUST fail unless `recoverThreshold > 0` and at least that many distinct current recovery controllers have supplied valid signatures.”

3. **High — §5.2: an empty combined slot exposes the vault publicly.**  
   No minimum part count, matching array length, or distinct-controller requirement is stated. With `controllers: []` and `parts: []`, the concatenated secret material is empty and the wrapping key is publicly computable from `I`. A one-part or repeated-controller slot also defeats the apparent multi-key requirement. Swift requires at least two parts.

   **Proposed wording:** “A combined slot MUST contain at least two parts and equally many distinct controller IDs. Part `i` MUST use controller `i`; a sealed part requires a raw controller with agreement, and a PRF part requires a WebAuthn controller. Any violation is `malformed`.”

4. **High — §5.2: sealed combined parts need independent secrets.**  
   The draft specifies only that their plaintext is 32 bytes. An implementer could reuse the ordinary sealed-slot construction, encrypting the vault seed as each part’s secret. Either controller could then decapsulate its own part and obtain the vault seed without satisfying the combined slot.

   **Proposed wording:** “Each sealed combined part MUST encrypt a fresh, independently generated random 32-byte secret. A part secret MUST NOT be the vault seed, derive from it, or be reused between parts or slots.”

5. **High — §§5.1, 6.2, 6.4: rotation does not prohibit historical vault reuse.**  
   Rotation is triggered by inequality with the current public identity. An `A → B → A` transition satisfies that test, although a removed controller may retain A’s seed. Future epochs would again become readable to that controller.

   **Proposed wording:** “Every vault rotation MUST generate a fresh independent seed that has never been used by this library. Both new public keys MUST differ from their counterparts in every previous vault. Reusing a historical vault identity or agreement key MUST be rejected.”

6. **High — §§5.2, 6.1–6.2: genesis slot construction is circular.**  
   Slot encryption requires `libraryID`, which hashes the exact genesis body, which contains the slot ciphertexts. Creating a genesis with usable slots therefore requires finding a hash fixed point. Implementers will otherwise invent incompatible exclusions or placeholder IDs.

   **Proposed wording:** “Genesis MUST contain an empty `slots` array. After computing the library ID, initialization MUST install usable slots through a control-authorized keyring entry before introducing epochs or content.”

7. **High — §6.3: one minority controller can permanently disable the library through layout.**  
   A single control key can raise layout beyond every deployed client’s support, even when keyring changes require several controllers. Because layout cannot decrease, the remaining controllers cannot repair this through an ordinary subsequent entry. `KeyringHolder` documents threshold enforcement for layout changes in the Swift reference.

   **Proposed wording:** “A layout entry requires the current control threshold of distinct valid control signatures. Every WebAuthn signature used for this authorization MUST have UV set.”

8. **High — §3.3: the origin profile excludes native Android assertions.**  
   Android native passkeys use `android:apk-key-hash:…` origins, which the HTTPS-only rule rejects. Rewriting `clientData` would invalidate its signature. [Android documents this origin format](https://developer.android.com/identity/passkeys/create-passkeys).

   Separately, `<label>.<rp>` leaves multi-label subdomains ambiguous; Swift explicitly accepts multiple nonempty labels.

   **Proposed wording:** “HTTPS origin matching MUST use the exact hostname rules defined here, including multiple nonempty subdomain labels and excluding ports, paths and user information. Native Android origins MUST match an explicit signed allowlist of application signing-certificate origins. Verifiers MUST NOT rewrite clientData or accept arbitrary native origins.”

9. **High — §§1, 6–7 and retained 0.3 admission rules: controller authority and content membership are not separated explicitly.**  
   The old root was automatically represented as an unrestricted member. The draft removes that root without defining its replacement in content admission. One implementation could grant every control controller unrestricted writes; another could require ordinary grants. A passkey-only controller also cannot satisfy the unchanged raw member identity/signature format.

   **Proposed wording:** “Controller status confers authority-entry permissions only. Content authors MUST have ordinary authenticated member identities and grants. Genesis creates no implicit member. Removing controller authority does not revoke a separate member grant. Vault identities MUST NOT be admitted as controllers or members.”

10. **Medium — §8: one ceremony per key cannot sign several different bodies.**  
    WebAuthn takes one challenge per assertion request. Returning several bodies in advance does not let one assertion satisfy their different body hashes. [The request API has a single challenge](https://www.w3.org/TR/webauthn-3/#dictionary-assertion-options).

    There is also a preparation dependency: approving historical shares requires opening the vault before their body exists; creating a PRF slot requires its PRF output before its containing body exists.

    **Proposed wording:** “Hosts MUST complete necessary vault unlock and PRF evaluation before finalizing dependent bodies. Each distinct body requires its own WebAuthn assertion. Implementations MUST NOT promise a single ceremony for actions requiring multiple bodies or prior PRF evaluation.”

11. **Medium — §5.2: “PRF with salt” does not specify portable PRF bytes.**  
    A web host may pass `salt` as WebAuthn `prf.eval.first`, while a native host passes it directly to CTAP `hmac-secret`. WebAuthn applies a domain-separated hash and selects the UV-associated PRF; those interpretations produce different outputs. [The PRF extension specifies this transformation](https://www.w3.org/TR/webauthn-3/#sctn-prf-extension).

    **Proposed wording:** “The stored salt is the exact WebAuthn PRF extension input. PRF output means its 32-byte `results.first`. A CTAP adapter MUST reproduce WebAuthn’s input transformation and UV-associated PRF selection. Missing support or results MUST fail explicitly, without fallback derivation. Slot creation MUST confirm successful opening before publication.”

12. **Medium — §§5.2, 8: successful decryption is not bound back to the advertised vault.**  
    The core is instructed to retain the decrypted seed without checking its derived public identity. A correctly authenticated slot can contain an unrelated 32-byte seed, causing false unlock success and subsequent failures or unusable changes. Swift’s `KeyringHolder.openMatching` performs this comparison.

    **Proposed wording:** “After opening any slot, the core MUST require exactly 32 plaintext bytes, derive the vault identity under §5.1, and compare both public keys with the current keyring’s vault. A mismatch MUST return `vaultLocked` and MUST NOT replace the session’s unlocked seed.”

13. **Medium — §3.1: the new envelope rules appear to apply to unchanged member records.**  
    The primary signer is universally defined as `body.by`, and every signer must be a controller. Requests and operations instead identify member signers and remain unchanged `/3` records. A literal implementation rejects every agent request and operation; a permissive implementation might accidentally extend controller assertions to content records.

    **Proposed wording:** “Section 3 applies exclusively to `colophon/authority/4` envelopes. Requests and operations retain their 0.3 member-signature rules and raw envelopes. They MUST NOT acquire authority through assertions or cosignatures.”

14. **Medium — §9 versus retained 0.3 §7.2: clean copy contradicts the import contract.**  
    Section 9 describes separately re-signed copied operations. The retained import contract defines a root-only signed parent with virtual children that are not separately signed. The root no longer exists, and no replacement authorization or location for `imported` is specified.

    **Failure scenario:** one copier emits ordinary operations with provenance fields, while another emits baseline import batches; replicas produce different revisions and retry behavior.

    **Proposed wording:** “Clean copy MUST use the destination import-batch contract, with source digests stored as encrypted evidence. Replace its root-only authorization with a control-threshold-authorized import permission binding the exact destination library, member, namespace and signed parent-body digest. Historical evidence MUST NOT confer destination authorship or authority.”

15. **Medium — §5.1: “every epoch” conflicts with immutable historical seals.**  
    After revocation or vault rotation, old authority records still contain seals for former members and vaults. Requiring every epoch to have exactly today’s eligible recipients makes ordinary history invalid, and conflicts with §6.2’s accumulation of historical shares.

    **Proposed wording:** “Every newly introduced epoch MUST be sealed to exactly the vault and eligible members at the introducing entry. Historical seals remain authenticated history. Later shares add only specifically authorized recipients; recipient-set changes do not invalidate earlier seals.”

16. **Medium — §3.3 step 5: the outer signature hash is implicit.**  
    Unlike §3.2, this step does not explicitly specify SHA-256 for ECDSA. An implementation using a prehashed verification API could treat `SHA-256(clientData)` as the signature digest, rather than hashing the complete signed message. Swift explicitly hashes that complete message.

    **Proposed wording:** “Let `M = authenticatorData ‖ SHA-256(exact clientData bytes)`. Verify ES256 using digest `SHA-256(M)`. A message-verification API receives M; a prehashed API receives SHA-256(M).”

17. **Medium — §§2.3, 3.3, 6: duplicate-map parsing can produce different authority decisions.**  
    Exact-byte signatures do not resolve duplicate JSON members or duplicate COSE labels. Different parsers can select different `threshold`, `roles`, `by`, `challenge`, or curve values from the same signed bytes.

    **Failure scenario:** a body containing duplicate threshold fields is approved under one parser’s interpretation and replayed under another’s.

    **Proposed wording:** “All protocol JSON objects and WebAuthn clientData MUST reject duplicate member names recursively. COSE maps MUST reject duplicate labels and trailing encoded objects. Invalid field types and prohibited fields MUST fail before authorization; implementations MUST NOT resolve duplicates by first-value or last-value selection.”

For §11:

1. **Sign custody and presence if they inform portable security displays or policy.** Define them as asserted metadata, not proof of hardware custody or human involvement.
2. **Yes.** Require the control threshold and WebAuthn UV for layout changes.
3. **No blanket refusal.** Warn based on actual surviving signing quorums and usable vault slots; simply counting two keys does not establish recoverability.
4. **Yes.** High-S acceptance is compatible with verification. Count distinct key IDs and use exact body digests for authority identity; preserve received signature bytes.
5. **Yes, optionally.** Sign `importedFrom` as a provenance claim for display, with no effect on identity, permissions, deduplication or trust.