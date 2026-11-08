Round-1 Codex findings:

- **C1 — RESOLVED:** §6.3 restricts recovery additions to `["approve"]` when recovery requires fewer signatures than control.
- **C2 — RESOLVED:** Recovery explicitly requires `recoverThreshold > 0`.
- **C3 — RESOLVED:** Combined slots require at least two distinct controllers and matching parts.
- **C4 — RESOLVED:** Sealed parts must contain fresh, independent random secrets, never the vault seed.
- **C5 — NOT RESOLVED:** §6.2 says “fresh,” but its §2.3 cross-reference prohibits cross-category reuse, not explicitly reuse of a historical vault within the vault category.
- **C6 — RESOLVED:** Slot context no longer includes the library ID, eliminating genesis circularity.
- **C7 — RESOLVED:** Layout changes require the control threshold.
- **C8 — RESOLVED:** Signed additional origins support Android, and HTTPS matching explicitly permits multiple subdomain labels.
- **C9 — RESOLVED:** Controllers confer no membership; genesis creates no member, and writers require separate identities and grants.
- **C10 — RESOLVED:** §8 orders unlocking and PRF evaluation before body construction and requires separate assertions for distinct bodies.
- **C11 — RESOLVED:** §5.2 specifies WebAuthn PRF inputs, outputs, CTAP transformation, UV-secret selection and explicit failure.
- **C12 — RESOLVED:** Opened seeds must derive both advertised vault public keys before replacing session state.
- **C13 — RESOLVED:** Assertions and cosignatures are confined to authority envelopes.
- **C14 — RESOLVED:** Clean copy now uses import batches under an explicit import grant, with source attribution confined to encrypted evidence.
- **C15 — RESOLVED:** Recipient exactness applies when an epoch is introduced; historical seals remain valid.
- **C16 — RESOLVED:** §3.3 explicitly defines the complete signed message and its outer SHA-256.
- **C17 — RESOLVED:** Recursive duplicate-name rejection, prohibited-field checks and duplicate COSE-label rejection are explicit.

Round-1 agy findings:

- **A1 — RESOLVED:** Lower-threshold recovery cannot add control or recovery roles.
- **A2 — NOT RESOLVED:** Rotation and demotion rules are clarified, but enforceable historical-vault freshness remains missing.
- **A3 — RESOLVED:** Cross-category key reuse is forbidden, and member records retain raw signatures.
- **A4 — RESOLVED:** Parts have separate contexts binding their index, kind and controller, with minimum-count and distinctness requirements.
- **A5 — RESOLVED:** Removing the library ID from slot context eliminates the circular dependency.
- **A6 — RESOLVED:** New PRF evaluations precede construction of their containing authority body.
- **A7 — RESOLVED:** Vault unlocking precedes construction of historical shares and the signing challenge.
- **A8 — RESOLVED:** RP syntax and HTTPS origin matching now exclude the identified injection characters and allow multiple labels.
- **A9 — NOT RESOLVED:** Mandatory rotation, retained demoted-controller slots and verification lowering are clarified, but the replay error for rotation violations remains unspecified.
- **A10 — RESOLVED:** Writers require membership, and `grant.import` replaces root-only import authorization.
- **A11 — RESOLVED:** The undefined per-operation `imported` field is removed; provenance resides in batch evidence.
- **A12 — RESOLVED:** Sequence 2 must initialize every namespace, and `rekey.epochs` is non-empty; revocation retains the 0.3 namespace-rotation rule.
- **A13 — RESOLVED:** Required thresholds, true-or-absent verification, absent unchanged-vault fields and non-empty cosignatures are specified.
- **A14 — RESOLVED:** Exact COSE shape, minimal encoding and high-S signature acceptance are normative.
- **A15 — NOT RESOLVED:** §6.3 requires cryptographic authentication before `newerFormat`, but does not require the relevant authorization quorum before that result.
- **A16 — RESOLVED:** Roles, slot cardinalities, part/controller correspondence and ciphertext sizes are specified for replay validation.
- **A17 — RESOLVED:** Every attached signature must verify, single-rule actions forbid cosignatures, and every quorum signer must hold the required role.

New findings, most severe first:

1. **High — §§2.3, 5.2: distinct controller IDs can share one opening key.**

   **Problem:** §2.3 enumerates categories rather than individual principals. Two controllers with different signing keys can therefore share an agreement key under a literal implementation. Distinct IDs in a combined slot do not establish distinct opening keys.

   **Failure scenario:** Controllers A and B have different signing keys but agreement point Q. One holder of Q’s private key opens both sealed parts of an A+B combined slot. Alternatively, removing A and rotating the vault still gives A access through B’s new slot.

   **Proposed wording:** “Every signing or agreement point MUST belong to exactly one individual principal throughout library history. Distinct controller IDs and distinct member IDs identify distinct principals, including within the same category. Sharing an agreement point between controllers is `malformed`. Repetition for the same retained principal is permitted. Each vault generation is a distinct principal; neither public key of a new vault may equal any public key previously assigned to another principal or vault generation.”

2. **High — §§5.2, 6.2: deleting an opening route does not revoke it.**

   **Problem:** Rotation is required only for controller removal or role loss. A control-authorized change can delete or replace slots while retaining the vault. Their historical ciphertexts still open the current seed.

   **Failure scenario:** A combined A+B slot is replaced with B+C to remove A from the required combination. All controllers retain their roles, so no rotation is required. A and B retrieve the old slot from authenticated history and continue opening every future epoch.

   **Proposed wording:** “When the vault is unchanged, every existing slot’s cryptographic fields MUST remain present and unchanged; labels and array order MAY change, and additional slots MAY be added. Deleting or changing an existing opening route MUST rotate the vault. Historical slots remain usable against their original vault; deleting them never revokes knowledge of that seed.”

3. **High — §2.1 versus retained operation/module rules: the global `null` prohibition breaks content semantics.**

   **Problem:** The prohibition applies to “all protocol JSON,” while the retained modules use explicit nulls. For example, the notes schemas allow nullable fields and use null to express operations that differ from omission.

   **Failure scenario:** Rust preserves a notes payload containing `topic: null` to clear its topic. An independent reader applies §2.1 recursively and rejects the operation as malformed. Removing the null changes the command’s meaning and its operation ID. Clean-copy evidence can encounter the same conflict.

   **Proposed wording:** “Duplicate-member rejection applies recursively to all protocol JSON. The omission and null restrictions in this section apply only to the protocol metadata fields defined here. Operation payloads, import evidence, historical alternatives and module values follow their respective schemas and MAY contain null. Unknown `clientData` members are ignored regardless of their JSON value.”

4. **Medium — §§2.1, 6.3, 11: unknown object fields have no acceptance policy.**

   **Problem:** Draft 2 defines outcomes for unknown enum values but no general rule for unknown field names. “Fields this document forbids” does not establish closed object schemas. The retained grant schema is closed, while other new objects are unspecified.

   **Failure scenario:** A signed controller descriptor contains an additional policy field. A Rust implementation using ordinary Serde deserialization ignores it; an independent implementation rejects it. If a future implementation interprets that field as a restriction, older readers can silently discard its security meaning.

   **Proposed wording:** “Authority bodies, envelopes, keyrings, controllers, key descriptors, slots and parts have closed field sets, including explicitly documented optional fields. An unknown field produces `newerFormat` only after authorization. For a known action, authorization MUST satisfy that action’s existing rule; an unknown action requires the current control rule, including threshold and UV. Failure to obtain that authorization produces `badSignature`. ClientData and extensible content payloads retain their explicitly stated exception policies.”

   This authorization gate also closes A15: a valid signature from one minority controller must not suffice to trigger an update requirement.

5. **Medium — §7 and retained 0.3 admission: “expiry ends future imports” has two incompatible meanings.**

   **Problem:** Remote admission in 0.3 compares the signed, author-claimed `created` against expiry. It does not establish publication time. Draft 2’s stronger statement can also be read as requiring rejection of imports first observed after expiry.

   **Failure scenario:** An importer creates a new batch after its grant expires, backdates `created`, and cites a pre-expiry authority sequence. A reader following 0.3 accepts it. Another reader enforces “ends future imports” using receipt time and rejects it. That second interpretation also rejects legitimately delayed synchronization.

   **Proposed wording:** “Import expiry follows ordinary operation expiry: remote admission checks the parent’s signed `created`, while local creation checks host `now`. Expiry does not prove publication time or prevent malicious backdating. To terminate acceptance of additional imports, revoke the copying member and explicitly preserve accepted parent-body digests through `kept`. Readers MUST NOT use first-observation time as an admission rule.”

6. **Medium — §§2.4, 5.2, 8: verification of a new PRF result is undefined and cannot be ordinary signature verification.**

   **Problem:** §2.4 promises that every PRF result is verified before use. During slot creation, the core has no existing authenticated ciphertext against which to check it. WebAuthn exposes PRF results as client extension outputs; the ordinary assertion signature is not a publicly verifiable proof of those plaintext results. [WebAuthn PRF processing](https://www.w3.org/TR/webauthn-3/#sctn-prf-extension).

   **Failure scenario:** An asynchronous host supplies another credential’s PRF result. The core encrypts the seed and “confirms” opening using that same supplied value. The check succeeds, but the advertised credential cannot subsequently open the slot.

   **Proposed wording:** “The host is trusted to obtain PRF outputs from the platform and bind each output to the exact pending request, selected credential and input salt. An assertion signature alone does not authenticate the plaintext PRF output. For an existing slot, the core validates the supplied result through AEAD authentication and the vault-identity comparison. Before publishing a newly created PRF opening route, the host MUST obtain a separate evaluation using the intended credential and stored salt, and the core MUST successfully open the slot with that result. Reusing the construction result is insufficient confirmation.”

7. **Medium — §6.3: recovery does not define how existing slots are compared.**

   **Problem:** Slots have no canonical array order. “Every existing slot [is] unchanged” can mean an unchanged array prefix, an ordered subsequence, a set or a multiset. The Swift reference uses multiset containment and permits reordering.

   **Failure scenario:** Recovery changes `[S1, S2]` to `[S2, S1, S3]`. One verifier accepts unchanged existing slots plus an addition; another rejects the changed ordering. Set comparison can also accidentally permit deletion of one duplicate slot.

   **Proposed wording:** “For recovery, existing slots MUST be preserved as a multiset, including multiplicity; their array positions MAY change. Compare slot values using their canonical JSON encodings. Existing controllers are compared by canonical JSON encoding of the complete descriptor. Additional slots MUST name only controllers introduced by this entry.”

8. **Medium — §10: the claimed conformance vectors do not exist.**

   **Problem:** `conformance/0.4/keys/` is absent. The document contains case descriptions, not byte-level vectors, and most refusal cases do not name an outcome. This leaves cryptographic interoperability and error precedence untestable.

   **Failure scenario:** Implementations disagree about combined-part indexing or derivation output, recovery slot comparison, or the error for an authorized removal without rotation. Both can claim to implement the listed cases.

   **Proposed wording:** “Before v1 freeze, publish the referenced vectors with exact input bytes, intermediate cryptographic values and expected results. Define part indices as zero-based, every part secret as exactly 32 bytes, and concatenation as `S0 ‖ … ‖ S(n−1)`. Every refusal vector MUST name one outcome. Structurally valid, adequately signed removal or demotion without required rotation MUST return `malformed`. Vectors MUST cover the unresolved round-1 cases and the new cases identified in this review.”

Freeze as v1: **Yes, after these new findings and the unresolved round-1 requirements are fixed, and the concrete conformance vectors are published.**