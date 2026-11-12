# Colophon 0.5: changes from 0.4, upgrade paths, review answers and deferred items

**Status:** companion to [colophon-0.5.md](colophon-0.5.md), revision 6, 2026-11-12. Section
numbers without a prefix are 0.5's. "0.4" means [colophon-0.4-keys.md](colophon-0.4-keys.md).
"Galley draft" is Galley's `docs/spec/colophon-0.5-draft.md` (draft 2). "The contract" is
Galley's `contracts/identity/one-identity.md` on branch `one-identity-contract` (head 172fe8f).
"Codex N" and "H/M/L N" are the two reviews of revision 1 (152d991), mapped in §G.1–§G.3.
"Opus R/M" and "Codex2 H/M" are the two reviews of revision 2 (9e90470), mapped in §G.4–§G.5.
"Codex3" and "Opus3" are the third reviews (of 365f52b), mapped in §G.7. "Opus4" and "Codex4" are the
fourth reviews (of 4032d44), mapped in §G.8. "Opus5" and "Codex5" are the fifth reviews (of
a1decc6) and "Builder N" the engine builder's implementation notes (`engine-0.5-foundation`,
04c0eef), mapped in §G.9. The worked theft and loss scenarios moved from the spec
to §H. Revision 4 replaces the
revision-2 and revision-3 recovery machinery (provisional keys, cancel, attempt 2,
counter-recovery, full recovery, the primary yield, the no-home digest tie-break) with one
mechanism: **pending transitions with veto** (spec §8.7). Rows of §A and §G below that name the
removed machinery are kept as history and marked superseded by §G.7; §F lists only the decisions
now in force.

## What existing keyrings actually are

This was checked in code, not only in documents.

- **Mike's library, used by Taupe and Marginalia, is not a 0.4 library.** The shipped apps run
  Marginalia's Swift `ColophonAuthority` (`origin/main` `c8280332`). That format is a 0.1 genesis
  with a root and a recovery identity, optionally followed by a root-signed `keyring` entry that
  adopts controllers.
  - The library ID is the first 32 hex of SHA-256 of the first body.
  - Keyring changes follow `verifyKeyringChange`, including the "Two Keys" rule: lowering
    `recoverThreshold` needs a recovery quorum.
  - Its slots use the labels `colophon/vault-prf/1`, `colophon/sealed-key/1` and others.
  - §16.3 now specifies this format normatively. The candidate's Swift vectors were replayed by
    that exact source, unmodified.
- The clean copy of Mike's library to 0.4 was never done (`docs/handoff-keys-04.md`). I could not
  inspect his devices, so whether his library has adopted a keyring, and which keys it holds, is
  unverified.
- That leaves two paths:
  - **in place from 0.4** (§16.1), for libraries made with the 0.4.0 SDK;
  - **succession from the Swift format** (§16.2), which is Mike's real path. It needs no new
    account and no new passkey.

## A. Changes from 0.4

"Breaking" means a 0.4 reader can't read what a 0.5 writer produces. At an upgraded library's
`upgrade` entry, a 0.4 reader stops with `newerFormat`. This was run on the released engine.
A 0.4 app that already holds state keeps its in-memory view and may keep writing `/3` records
that cite earlier authority; 0.5 admits those, so nothing is lost (H-review note, §16.1).

| # | Change | Why | Breaking | Upgrade path for a 0.4 library |
| --- | --- | --- | --- | --- |
| 1 | 64-hex account IDs (§5.1) | IDs are used across accounts; 128 bits invites collisions | Yes | Same genesis, so the old ID is the prefix; stated in the signed `upgrade` entry |
| 2 | `upgrade` entry, then `/5` (§16.1) | One signed step that keeps everything | By design | Append once, after every app reads 0.5 |
| 3 | `addThreshold` and the add rule, with provisional additions below threshold (§8.4) | Adding a passkey is one approval; below the control threshold an addition is approve-only, has no slot and expires unless confirmed | Yes | Chosen in the upgrade keyring |
| 4 | Possession proofs, `additions` (§4.1, §8.4) | No one can list someone else's public key as a controller (contract R-A1) | Yes | The upgrade entry and keys carried over by succession are exempt |
| 5 | Recovery-set rule, recovery delay, receipts and the cancel rule (§8.4, §13.5) | One control key can no longer remove recovery. One stolen recovery key leaves the owner a delay to cancel (H2, Codex 9) | Yes | `recoveryDelay` is set in the upgrade keyring (default 72 h; at least 1 h once there's a home) |
| 6 | Control rule counts the larger of the old and new `threshold` (§8.4) | Anti-weakening (contract 8.2) | Yes | — |
| 7 | Monotonic `issued` (§8.1) | Delays and expiries can't be backdated | Yes | Existing 0.4 entries are not re-checked |
| 8 | `countBy`, `holder` (§6.1–§6.2) | Company thresholds count people (H6) | Yes | `keys` keeps 0.4 behaviour |
| 9 | Roles `sign` and `audiences` (§6.1) | A key made outside an authority origin (for example a staging passkey) can only sign calls at named audiences (contract R-A2) | Yes | Optional |
| 10 | Account `policy`, including `memberRule`, `primaryHome` and `recoveryDelay` (§6.3, §18) | Policy is configuration with a default, a range and a holder of the right to change it | Yes | In the upgrade keyring |
| 11 | Authority origins by default; `authorityOrigins`; call origins; rules on `rp` (§3.2, §4.3) | PRF and signatures are available to every origin under an `rp` (H4, Codex 3) | Yes | Absent pins become the strict default: authority signatures only from `https://<rp>` or listed platform origins |
| 12 | Grants carry `terms` (§9.2, §10) | Per-namespace access, `propose`, `kinds`, conditions, `services`, `depth`, `serves` | Yes | Converted mechanically (§16.1) |
| 13 | Request `/5` with `custody`, `operator`; commit-then-reveal pairing (§7.3, §9.1) | A 20-bit code over one key let a relay substitute a key in 30 seconds (H5, Codex 4). Swift `custody`/`keyOperator` get a 0.5 form | Yes | New members use `/5` |
| 14 | `renew` (only extends) and `memberRule` (§9.4, §6.3) | Agents renew; companies can require the control rule for members (M1) | Additive | — |
| 15 | `revoke` with `kept` plus up to 16 `heads`, defined walk (§9.5) | Bounded revocation that loses no fork branch (M5, Codex 7) | Yes | `/3` records keep exact digests |
| 16 | Operation header `/5` with `account`, `level`, `previous` (§11.2) | Full ID, proposals, author chains | Yes | `/3` fenced by authority seq (§11.5) |
| 17 | Proposals; acceptance is never final (§11.6) | D25; M6 | Additive | — |
| 18 | Links and calls with a shared, atomic replay store (§12) | Sessions; one signed shape for acting at a system (M3) | Additive | — |
| 19 | `endSessions` (§9.6) | D38 | Additive | — |
| 20 | Homes, a primary home, heads, receipts, equivocation evidence (§13, §14) | Ordering without forks across homes (H3); freshness (M4); R-A7 | Additive | Appoint homes by grant |
| 21 | Forks: `refused:fork` on both branches, `resolve` (§8.6) | Verifiers holding different branches can't diverge silently (H3, Codex 11) | Additive | — |
| 22 | Succession from a single final entry; terminal `successor`; `migration` entry; the Swift format specified (§15, §16.3) | H1, M2, Codex 6, 8 | Yes (`importedFrom` removed) | Swift path (§16.2) |
| 23 | Genesis may declare no namespaces (§8.2) | Identity-only and company accounts | Additive | — |
| 24 | Bounds, strict dates, canonical bytes and base64; signature bytes never identifiers (§2) | L6, L7, R-A6, R-A11 | Yes for `/5` | — |
| 25 | Seed transfer to a new device (§7.4) | Adding a passkey where no controller has the seed | Additive | — |
| 26 | Restricted vault HPKE open (§17.2) | Backups without exporting the seed (R10); not an oracle for members (L8) | Additive | — |
| 27 | Removing a never-slotted controller needs no rotation; re-adding a removed controller is allowed with new slots (§8.3) | M1, M8 | Additive | — |
| 28 | Attempt-2 recovery, counter-recovery, full recovery; removal of delayed keys only by cancel (§8.4) | Repeated cancel and dead homes (rev-2 reviews) | Additive | — |
| 29 | Policy classification: which changes need the recovery-set rule (§6.3) | Missing triggers (rev-2 reviews) | Yes | Applies to entries after the upgrade |
| 30 | Fork classification: evidence, vouched forks, no-home priority; body-byte equality (§2.2, §8.6) | Removed keys and narrow roles could freeze an account | Yes | — |
| 31 | Succession: publication places, original identities after rotation, recovery-added signers delayed with refusal, persistence, preflight, drain (§15) | Rev-2 reviews R6–R8, M-b–M-f, Codex2 H3 | Yes | Swift path (§16.2) |
| 32 | Portability floor of 65,536 entries and 256 MiB; documented service limits (§2.4) | Unbounded first-contact work | Yes | — |

Unchanged and restated in full: strict parsing, key descriptors, one key one principal (now
explicitly across time), private-key work in the host, COSE, envelopes, `raw` and `webauthn`
checks (now with a stated flags and counter policy), vault and slots with their labels, PRF
rules, rotation, the verification order, import grants, epochs, operation IDs, fold order,
clocks and admission.

### A.1 Revision 4

| # | Change | Why | Breaking |
| --- | --- | --- | --- |
| 33 | **Pending transitions with veto** (§8.4, §8.7): every authority-reducing or authority-seizing change is a signed transition, stored outside the sequence and received by homes. It activates after `recoveryDelay` from the latest `headQuorum` receipts unless vetoed. Vetoes need as many keys as signed; escalation v(K); full set immediate; `activate` and `vetoed` entries ordered first | Codex3 H1–H3; Opus3 H1–H3; one mechanism instead of six | Yes |
| 34 | Removed: provisional controllers and `until`; cancel, attempt 2, counter-recovery; the separate full-recovery rule; recovery receipts on entries; primary yield; no-home digest tie-break; the separate succession refusal | Superseded by 33 | Yes |
| 35 | Immediate `keyring` entries only add approve or sign keys, add slots, relabel and tighten; headroom of 8 controllers reserved for transitions | Opus3 H2 | Yes |
| 36 | Swift succession waits for a veto window before F; signed by the keys the app actually holds; no original identities | Opus3 (rule 5 unmeetable: `protect()`, `recover()`, `rotateRecovery()`), Codex3 M6 | Yes |
| 37 | Replay store state machine; signature budget in the portability floor | Codex3 M7, M9 | Yes |
| 38 | §16.3 DER: the probe error corrected; §4.3 step 5 applies unchanged | Probe re-run (README) | — |

### A.2 Revision 5

| # | Change | Why |
| --- | --- | --- |
| 39 | Transitions are evaluated against the state before their `activate` (rule, consent, escalation, homes, "no home"); the delay is the larger of anchor and activation | Opus4 H1 |
| 40 | `signers` in transition and veto bodies; determined `activate`/`vetoed` bytes; due time = `headQuorum`-th smallest receipt; ordering of different transitions; `activate` never displaces entries ordered before its due time | Opus4 H6–H8 |
| 41 | Composite `change` (several components, atomic, union of rules); vault rotation inside a removal with slot rebasing | Codex4 High 2, Opus4 H3 |
| 42 | Vetoes need `headQuorum` receipts; activations are final only when every current home's head covers them; provisional additions don't count for calls; a later valid veto rolls back | Codex4 High 3 |
| 43 | Immediate class narrowed: a key tightens only its own authentication; `layout`, `migration`, unknown changes are transitions; rate limits; one epoch per namespace per `rekey`; headroom for slots | Opus4 H2, H4, M7, M9; Codex4 High 1 |
| 44 | `suspend` | Opus4 M1, the architect's decision 5 |
| 45 | Recover keys read the history; §13.4 covers transitions | Opus4 H5 |
| 46 | Full set (a)/(b), removed keys counted; counting units | Opus4 H9, Codex4 Medium 1 |
| 47 | Escalation re-checked before activation; reset only by a compliant activation; no-op transitions void; per counting unit | Codex4 High 4 |
| 48 | Reference setup: two homes (person), three at quorum 2 (company); a control key off the phone | Opus4 M2, M3, H9 |
| 49 | Notices: polling interval, recovery keys first, members of a removed key listed | Opus4 M5, M11 |
| 50 | Succession: receipt window from the appointing entry; vetoers bounded; vetoes recorded as `vetoed` in the successor; competing attempts and premature freezes; root alone signs a root library's hand-over | Opus4 H10, M6; Codex4 Medium 4 |
| 51 | Replay reservation after step 7; `abandoned` terminal state; external-object limits and an all-signature budget in the floor | Opus4 M10; Codex4 Mediums 5, 6 |

### A.3 Revision 6

| # | Change | Why |
| --- | --- | --- |
| 52 | Recording entries are once only per transition, carry every object they rely on (`vetoed` also `transitionReceipts`), have exact schemas, and are `malformed` when not determined, out of time (7 days, checkable) or carrying invalid receipts; v(u) counts distinct transitions | Opus5 H1, M4, M8 |
| 53 | Due time = `issued` + 300 s + delay once `headQuorum` receipts exist; veto deadline 300 s earlier; receipts forwarded between homes and chosen by lowest home ID; two recordings that differ only in receipts ordered by digest; displaced signed entries go back to their signers | Opus5 H3; Codex5 Medium 7 |
| 54 | Finality judged against the homes current before the activation, in order; a full set against the homes after it; a final activation is never displaced (a later `vetoed` is evidence); whatever a provisional activation adds counts for nothing; rollback removes the suffix only; the recovery rule may change homes, so a gone home can be revoked by one full set | Opus5 H2; Codex5 High 1, High 2, Medium 6 |
| 55 | `suspend` carries its transition and receipts; it ends computably; a void transition can't be receipted or cited; one per unit; suspended keys read the history; §12.3 applies suspensions after S | Opus5 H4 |
| 56 | `policy.rate`, checked by every verifier; planted keys charged to their adder; four controllers per addition; revocations outside the account limit | Opus5 H5; Codex5 Medium 8 |
| 57 | `keep` | Opus5 M1 |
| 58 | Homes store an `activate` they didn't receipt only if they saw it within its window (or were down) | Opus5 M2 |
| 59 | Vault change carries `previousVault` in the transition; its `activate` is determined; a `rekey` follows; slots dropped by rebasing rebuilt by the host that holds the new seed | Opus5 M3; Codex5 High 3 |
| 60 | Composite rule: one rule for every component | Opus5 M6; Codex5 Medium 5 |
| 61 | Succession: deterministic window and due time; vetoers within the delay before the genesis; `successionVetoed`; no tie; any layout above 2 freezes | Opus5 M5; Codex5 High 4 |
| 62 | Roles carry over exactly on upgrade; reference setup for new accounts separate; a phone-only person gets a security key with `control` + `recover`; a paragraph hosts can show | The architect's reference-setup decision; Opus5 Q3 |
| 63 | One verification order (§1); the builder's 28 ambiguities settled (§G.9) | Builder |
| 64 | Rationale, warning wording, host interface, not-in-version and the review log moved to the non-normative guide; persisted verifier state (§17.2) | Opus5 Q9; Codex5 Medium 7 |

## B. Galley's requirements

### B.1 Contract §13 (R1–R13, revision 1 of the contract)

| Req | Settled | Where |
| --- | --- | --- |
| R1 verifier output | Yes, extended by R-A5 | §17.2 |
| R2 standalone WebAuthn check | Yes; `badSignature` plus the failed check | §17.2 |
| R3 outside resources | `services` audiences; **no `environments` term**: an environment is an audience, and each deployment MUST have its own (Codex 10) | §10.1 |
| R4 signed checkpoint | **Refused**: a checkpoint can't be checked without the history it replaces, or it makes a home a trust root. Incremental verification is specified exactly instead (§13.3). Galley MUST drop any total-entry cap for first contact (Codex 11); 0.5 sets none and requires support for ≥ 1,048,576 entries | §2.4, §13.3 |
| R5 several homes | `headQuorum`, primary home, ancestry comparison | §6.3, §13.1, §13.3 |
| R6 reading history | `colophon.history.read`; `policy.history`; applies to relay paths too (M7) | §13.4 |
| R7 bodies stay JSON | Yes | §2.1 |
| R8 origin pin | `authorityOrigins`; strict default when absent | §3.1, §4.3 |
| R9 exact `https://` origins | Yes | §3.1 |
| R10 vault key agreement | HPKE open only, restricted to the host (L8); never raw ECDH | §17.2 |
| R11 `user.id` | Yes | §17.4 |
| R12 head body | Yes | §13.2 |
| R13 home in the first upload | Yes | §13.1 |

### B.2 Contract §13.2 (R-A1–R-A11)

| Req | Settled | Where |
| --- | --- | --- |
| R-A1 added key co-signs | Yes: `additions` possession proofs, from an authority origin. Exempt: the `upgrade` entry, and keys carried over by a verified succession | §4.1, §8.4 |
| R-A2 audience limits, sign-only role | Yes: role `sign` with `audiences`; never signs authority, never counts, no slot; added under the add rule at any threshold; its possession proof may come from its own `rp` | §6.1, §8.4, §12.3 |
| R-A3 anti-weakening and delay as authority rules | Yes: recovery-set rule; the control rule counts the larger threshold; delay plus cancel. **Range decided:** `recoveryDelay` is 0–2,592,000 s and **at least 3,600 s while the account has any home**; 0 only without a home; default 259,200 s (72 h, the contract's figure). Without a home nothing can attest the time a recovery arrived, so a non-zero delay would be a promise nobody keeps. With a home, an hour is the least time an owner needs to see a notice and cancel. The contract's "never zero" is the right rule for every account that has a home | §6.3, §8.4, §13.5, §18 |
| R-A4 agents never controllers, across time | Yes, explicit in §3.3 rule 2; vectors `member-key-as-controller` and `former-controller-as-member` | §3.3, §9.7 |
| R-A5 per-entry signers in the output | Yes: primary, cosigners, possession, handover, the rule met, receipt | §17.2 |
| R-A6 date grammar for `expires` | Yes: §2.2 applies everywhere; invalid dates are `malformed` | §2.2, §10.1 |
| R-A7 equivocation evidence | Yes: `colophon/equivocation/5` | §13.3 |
| R-A8 minimum versions, downgrade | Yes: the accepted markers are listed, a 0.5 account is never read under 0.4 rules, and later retirement is by authority entry | §20 |
| R-A9 pairwise references | **Refused, plainly stated:** one key across accounts is linkable by anyone who sees both histories. An account ID is a genesis digest and the history is shown to verifiers, so per-audience IDs would need a new identity layer. Use different keys for accounts that must not be linkable | §3.3 |
| R-A10 counter and flags | Yes: counter MAY be recorded, never refused on; other flags and extension bytes ignored | §4.3 |
| R-A11 signatures never identifiers | Yes | §2.2 |

### B.3 The contract's origin layout

The contract puts authority ceremonies and PRF on `keys.id.luff.works`, calls on
`sign.id.luff.works`, and nothing scripted on the bare `id.luff.works`. Against §3.2 and §4.3:

- **Signatures: sound.** `authorityOrigins` listing only `https://keys.id.luff.works`, the bare
  `https://id.luff.works` (for native-app assertions) and native platform origins means the call
  origin can never produce an authority signature.
- **Vault access: not separated, and it can't be.** PRF is available to every origin a browser
  lets use the `rp`, which includes `sign.id.luff.works`. The call origin can therefore open every
  `prf` slot. This is now normative (§3.2): ceremony and call origins under one `rp` separate
  authority signatures, not vault access. The only way to keep call-origin code from the vault is
  a different `rp`, which means different passkeys. The contract's §5.6 already says this; it
  should treat the call origin as vault-critical, with the same deployment controls as the
  authority origin.
- Also normative now: no origin under the `rp` may run code of a non-production release
  (§3.2). The contract's staging ceremonies through the production call origin are allowed,
  because the code there is production's; staging's own passkeys need a different `rp` and are
  `sign` controllers.

### B.4 What Galley's contract must change (from the second Opus review, §6)

| # | Contract | Conflict | 0.5 rule the contract must follow |
| --- | --- | --- | --- |
| 1 | §0.1, R-A3: delay "1 h – 30 d, never 0" | 0.5 allows 0 only without a home | Keep "never 0" as Galley's reference default, but say that 0.5 accounts without a home have no delay (§8.4) and that the reference setup appoints a home first (§18) |
| 2 | §8.3: only `control` additions delayed; approve-only immediate; "any existing controller" cancels | 0.5 delays every signature by a recovery-added key, and only a pre-existing, not recovery-added `control` key cancels; attempt 2 needs a counter-recovery | §8.4 delay, cancel and attempt 2 |
| 3 | §2 step 6: home allows 300 s ahead; no primary ordering, receipts or notices | 0.5: 60 s ahead; ±300 s for recovery and cancel entries; primary ordering (421); per-home receipts; notices | §13.1, §13.5, §14 |
| 4 | §3.2–§3.3: a diverging home "stops counting" | 0.5 classifies the conflict (§8.6): equivocation evidence; recovery at a non-primary home; a vouched fork (`refused:fork` until `resolve`); or no-home priority | §8.6, and handle `resolve` |
| 5 | §4.6: accepts bare `https://<rp>` and `origins` for calls | 0.5 accepts only configured call-ceremony origins | §12.3 step 5 |
| 6 | §4.4 consent omits `additions` | Possession proofs make every non-carried controller consenting; carried-over Swift keys are exempt and must be treated as consented by the verified succession | §8.4 possession |
| 7 | §4.5 "until 0.5 has R-A2" | R-A2 is in 0.5; a staging-made key needs its own `rp` and is `sign` | §3.2, §6.1, §17.3 |
| 8 | §6.1 agent grants fixed to the single rule | Companies with `memberRule` `control` need the control rule | §8.4 |
| 9 | §7.3 bind quorum counts keys; §0.1 company default omits `countBy`, `memberRule` | 0.5 counts holders under `countBy: holders` | §6.2, §18 |
| 10 | §7.5 bind moves on a verified succession alone | 0.5 requires the `migration` entry too | §15.4 |
| 11 | §11.2: no freezing entry; no possession for non-carried keys; root library signed by root only; no Two Keys recover signers; no `migration`; the passkey role swap without recovery consent | All required by 0.5 | §15.1 rules 4–6, §15.3, §16.2 |
| 12 | §13.2 still lists R-A1–R-A11 as missing | All are in 0.5 except R-A9 (refused); R4 refused | Update the citations |
| 13 | `reference/verifier.ts`: `decodeEntries(list, max = 256)` and a 1 MiB history limit | 0.5's portability floor is 65,536 entries and 256 MiB | §2.4 |

Revision 4 adds these for the contract:

| # | Contract | 0.5 revision 4 |
| --- | --- | --- |
| 14 | §8.2, §8.3 anti-weakening and delay | Replace with the pending-transition rules (§8.4 table, §8.7): delay from the latest `headQuorum` receipts, veto by any non-signing control or recover key with as many keys as signed, escalation, full set immediate. The contract's "never 0" is the 0.5 rule for every account with a home; its "approve-only additions take effect at once" matches the immediate class |
| 15 | §11.2 step order | Genesis, home, receipts of the genesis, veto window, then F, drain, `migration`. Handover by the current root and recovery kit (root library) or the control quorum (keyring library); no original identities |
| 16 | Its own homes | Must receipt transitions and vetoes, append `activate` and `vetoed` first, and serve `transitions/` |
| 17 | Agent approvals | Grants with `services` remain immediate under the single rule; homes and `import` grants are pending |

Revision 5 adds:

| # | Contract | 0.5 revision 5 |
| --- | --- | --- |
| 18 | Approval card and sign-in for a person whose devices are gone | A `recover`-only key may call `colophon.history.read`; Galley's home must accept it |
| 19 | Galley's home | Store only `ok` objects; enforce the rate limits; store `activate` only for transitions it receipted or saw a delay earlier; push notices to registered devices; serve `transitions/` |
| 20 | Using a newly added controller | Wait for finality (every current home's head covers its activation) before accepting its calls |
| 21 | §11.2 | Handover by the current root alone (root library); the successor's homes receipt the genesis within 300 s of their own appointment; vetoes become `vetoed` entries in the successor |
| 22 | Reference deployment | Two homes for people (different operators); the identity service may be one of them |

Revision 6 adds:

| # | Contract | 0.5 revision 6 |
| --- | --- | --- |
| 23 | Galley's home | Forward every transition, veto and receipt to the other homes; sign at most one receipt per object; append recording entries with exactly the chosen receipts (`vetoed` carries `transitionReceipts`); store an `activate` it didn't receipt only if it saw the transition within 300 s of its `issued`; refuse entries over `policy.rate`; never store an `activate` after holding a valid veto |
| 24 | Countdowns in the approval card | Due = transition `issued` + 300 s + delay; veto deadline = `issued` + delay |
| 25 | Using a newly added controller or home | Count it for nothing (no signatures, no receipts, no heads, no calls) until its activation is final against the homes current before it |
| 26 | Policy parsing | `policy.rate` is a required field |
| 27 | §11.2 and the Taupe/Marginalia upgrade | Roles carry over exactly; the reference roles are an offered pending transition, never applied by the tool. Succession window from the first entry with `headQuorum` homes; vetoes become `successionVetoed` entries; any key current within the delay before the genesis may veto |
| 28 | Phone-only people | Offer one security key with `control` + `recover` |

Two further points the contract needs:

- **Accounts as controllers** (contract 0.1, 1.4, 7.1) aren't in 0.5 (§C). A company's controllers
  are its people's keys, with `holder` and `countBy: holders`.
- **A home is whatever the owner chooses.** The contract's reference home is LUFF's identity
  service; 0.5 assumes none. The reference setup must appoint one before any recovery key is
  added (§18).

## C. Deliberately left for later

| Item | Why not in 0.5 |
| --- | --- |
| Accounts as controllers, cross-account signatures | A signature by "account C" is only as current as the verifier's view of C. Closing that (Galley Q47) needs an admission witness whose trust claim is undecided. One key may control many accounts instead. |
| Guarded state (authorities, claims, spending limits) | The retry semantics are unsettled (W0 closure), and Galley's kernel is today's authority. |
| Modules as WASM, releases, attestations, layers | No deterministic metering profile exists (Q49; colophon#2). |
| Session-authored records, epoch hand-off to sessions | Sessions act through calls; services write records under their own member keys. |
| `requires` and custody or presence evidence | No attestation format; a term nobody can check is worse than none. `custody` is display only. |
| Signed history checkpoints | See R4. |
| Witnesses beyond `headQuorum`; pairwise IDs | See §13.3 and R-A9. |
| Pre-rotation | Recovery covers a stolen key; passkeys can't be generated ahead of their ceremony. |
| Proposing without reading (Q46) | Needs an inbox key per namespace. |
| A strict online write budget | Needs guarded state. |
| Requiring a combined slot for web-reachable passkeys (Codex 3) | Offered as a setting (§7.2), not required. The owner's default is that one key opens the data. |

## D. Deferred and open items found in the repositories

| Item | Where | 0.5 |
| --- | --- | --- |
| "Recovery rotation, stewards and delegated sub-grants are deferred" | 0.3 §4 | Rotation: 0.4. Stewards: thresholds and holders. Sub-grants: links. |
| One immutable grant per identity | 0.3 §4 | `renew` extends; scope changes need a new key. |
| No read here and write there | 0.3 §6 | Per-entry access. |
| A strict budget needs a sequencer | 0.3 §5 | Left (§C). |
| Custody and presence as signed fields | 0.4 §11 | Left; `custody` is display. |
| D-F2-1 cold replay | `docs/performance.md` | Incremental verification (§13.3); not re-measured. |
| PRF from registration output | 0.4 §10 | Unchanged rule. |
| Keep sets grow | `docs/handoff-engine.md` | Author chains with up to 16 heads. |
| No global freshness or anti-rollback | `docs/handoff-engine.md`; 0.3 §7.1 | Heads, high-water marks, primary home, quorum; local-cache rollback by an attacker who controls local storage is out of scope. |
| Relocation, recovery and leave protocols | `docs/handoff-blobs.md` | Homes, succession, migration entry. |
| Android packaging, blob GC and other host gaps | `docs/followups.md`, `docs/handoff-blobs.md` | Host work; unchanged. |
| Domain open questions | `docs/domains/*.md` | Not formats; unchanged. |
| W1 findings (22 rows) | `spec/colophon-0.5-findings.md` | §E. |
| Galley draft §15 items 1–9; Q46–Q50 | Galley | Q46 settled (propose includes read); Q48 settled (author chains); the rest left with their features. |
| W0 retry contradictions | Galley | For calls, §12.4; the guarded half is left with guarded state. |
| Draft-1 vectors under `conformance/0.5/speaks-for` and `terms` | colophon `main` | Contradict 0.5 (L1). Moving them means changing the test that reads them, so it is implementation step 0, before freeze. |
| Swift "Two Keys" lowering rule | `ColophonAuthority` | Adopted, generalized as the recovery-set rule. |

## E. The W1 findings, settled

| Finding | 0.5 |
| --- | --- |
| Link embedding | Base64 of the canonical envelope (§2.2); links travel in the call. |
| Canonical base64 | Refused otherwise (§2.2). |
| Unknown terms vs order | Pipeline (§1). |
| Fetching | The host's; the core returns `unavailable`. |
| Two expiries | Members `terms.expires`; links their own `expires`. |
| Error codes | §19. |
| Parent lifetime, depth | `refused:expired`, `refused:notNarrower`. |
| Session on first link; `unguarded` | First link only; no `unguarded` success. |
| `asOf` vs latest | Evaluated at S, the highest seq the heads cover, with held removals applied (§12.3). |
| Audience, replay, window codes | Separate reasons. |
| `body` digest | `args` in plaintext. |
| Nonce cache | Shared replay store, 7,200 s, keyed with the acting key (§12.4). |
| Name bounds | §10.1. |
| Duplicates, empty arrays | Distinct everywhere; omit instead of empty. |
| `requires`/`uv` | Removed. |
| Absent bounds | Unbounded in member terms. |
| Condition inclusion | Exact canonical equality. |
| `guard:` and `colophon.sign` purposes | Gone with guarded state and modules. |
| Paths, empty logic, numbers, predicate counting | As W1 read them (§10.4). |

## F. Design forks decided

The decisions in force at revision 6. Superseded forks (cancel, attempt 2, provisional keys,
"what a delay blocks", full recovery, the no-home digest tie-break) are in §G.1–§G.7 as history.

| Fork | Chosen | Rejected, and why |
| --- | --- | --- |
| 0.4 → 0.5 | In place | Clean copy: loses members and IDs for nothing. |
| Swift → 0.5 | Clean copy with a frozen predecessor, a verified hand-over and a migration entry; roles carried over exactly | Teaching every verifier to read Swift content forever; guessing the owner's intended roles. |
| Succession anchor | The predecessor's single final entry, at `head.seq + 1` | The final entry at `head`: a cycle with the genesis digest. |
| Recovery | One mechanism: any change that isn't immediate is a pending transition, due at `issued` + 300 s + delay, vetoable until 300 s before that by as many non-signing units, with escalation | Special recovery entries, cancels and attempts (revisions 2–3); `max(2, threshold)` recovery signers, which overrides the owner's one-key default. |
| Immediate class | Member grants, approve and sign additions (four per entry), relabels and self-tightening, bounded by a rate limit every verifier checks and charged to the planting key | Everything pending: a new browser couldn't sign in with one approval; a rate limit enforced only by the primary, which a thief could use to block revocations. |
| Suspension | An explicit entry by a signer of a valid pending removal, ending computably | Automatic suspension: one recovery key could cut off every owner key for the delay. |
| Time witness | Receipts from `headQuorum` homes within 300 s of `issued`; the due time doesn't depend on which receipts a home holds | Due time from the receipts held (homes disagree); `issued` alone (backdatable). |
| Finality | Every home current before the activation covers it, in order; a full set needs the homes after it; final activations are never displaced | Homes after the activation for every transition: a thief who revokes the honest home finalizes with the hostile one alone (Opus5 H2's text, see §G.9). |
| Rollback | Removes the provisional activation and its suffix; nothing it added has signed | Re-verifying the suffix at new positions: signed entries can't move. |
| Gone home | One full-set transition revokes it (the recovery rule may change homes) | No exit (additions stuck for ever); a separate override entry. |
| Vault change | `previousVault` in the transition, a determined `activate`, then a `rekey` | Resealing every epoch inside a signed `activate`: overflows 1 MiB in long-lived accounts and needs one device. |
| Fork resolution | `resolve` under the pre-fork keyring | First-seen wins: diverges across verifiers. |
| PRF exposure | Stated, with deployment rules and combined slots as a setting | A mandatory combined slot or an origin allowlist the account can't enforce. |
| Freshness | Primary home plus `headQuorum`, stated limits | A pinned witness or signed checkpoint: a new trust root. |
| Pairing | Commit-then-reveal SAS, or QR | A PAKE: no allowlisted implementation, same bound per attempt. |
| Epoch and slot labels | Unchanged `/3` and `/4` labels | New labels: no gain, double code. |
| No home | Allowed, with a MUST warning: no delay, no veto, no theft safety | Mandatory homes: would override the owner's choice. |
| Holders | Labels attested by the controllers; counting units everywhere | A bound person identity: a second account system. |
| History bound | Portability floor; services answer `unavailable` beyond their limits | A signed checkpoint (R4). |
| Swift DER | §4.3 step 5 exactly (CryptoKit on macOS 27 accepts the same set); duplicate `clientData` refused | A lenient form nobody needs. |
| Root library hand-over | The root alone; the veto window protects the owner | Root and kit together: friction without stopping either thief. |

## G. Changes after review

### G.1 Codex (Daybreak Blue)

| Finding | Settled in | How |
| --- | --- | --- |
| 1 Lower-threshold add | §6.1, §8.4 | Provisional additions (approve only, `until`, no slot); a control-rule entry confirms. §6.1 states plainly what one approve key can do. |
| 2 One recovery key gives full control | §8.4, §13.5, §18 | Rejected as specified (§F). Delay, receipt, cancel and recovery-set rule instead. |
| 3 PRF via a compromised origin | §3.2, §7.2 | Stated normatively, with the `rp` deployment rule and combined slots as a setting. The mandatory form was rejected (§F). |
| 4 Pairing brute force | §7.3 | Commit-then-reveal with both nonces; one attempt per commitment; QR alternative. |
| 5 Home freezes authority | §13.1, §13.3 | Primary replacement under the control rule, quorum, stale heads never used, and the limit at quorum 1 stated. A checkpoint was rejected (§F). |
| 6 Swift root hijack | §15.1 rule 5 | A root library needs the recovery identity in `handover`. |
| 7 Author forks | §9.5, §11.2 | Up to 16 heads; a missing intermediate is held; one writer per key; several maximal heads stop writing. |
| 8 Migration completeness | §15.3, §15.4, §16.3, §17.2 | `migration` entry, required for principal moves; the Swift verifier is a pure function in every binding. |
| 9 Recovery weakening | §8.4 | Recovery-set rule. |
| 10 Deployment-bound audience | §10.1 | Each deployment MUST have its own canonical audience; the text no longer overstates it. |
| 11 Proof cap vs no checkpoint | §2.4, §13.3, §B.1 R4 | No total cap; complete verification for first contact; incremental verification from persisted state. |
| Low: vault HPKE underspecified | §17.2 | Envelope, `info`, AAD and bounds specified. |
| Low: operation header bound | §2.4 | 16 MiB. |
| Low: protocol markers | §1, §12.3 | An unknown marker is `malformed`. |
| Low: vectors insufficient | §21, candidate README | 215 new files; the rest is implementation step V1, and freeze waits for it. |

### G.2 Independent attack review

| Finding | Settled in | How |
| --- | --- | --- |
| H1 Succession | §15.1–§15.4, §16.2, §16.3 | Final entry, uniqueness and fork refusal, recovery quorum when lowering. Deviation: the anchor is at `head.seq + 1` (§F). |
| H2 Anti-weakening | §8.1, §8.4, §13.1, §13.5, §18 | Monotonic `issued`, recovery-set rule, `recoveryDelay`, receipts, cancel. Deviations in §F. |
| H3 Forks across homes | §8.6, §13.1, §13.3 | Primary home; `refused:fork` on both branches; `resolve`. |
| H4 Origins | §3.1, §3.2, §4.3, §7.2, §12.3, §18 | All four rules adopted; the staging origin removed from the example. |
| H5 Pairing | §7.3, §7.4, §9.1 | As required, with the nonces also in the transfer label. |
| H6 Companies | §6.1, §6.2, §6.4, §18 | `holder`, `countBy`, reference company setup and warnings. |
| M1 Approve power | §6.1, §6.3, §8.3, §8.4, §9.4, §17.5 | Stated; `memberRule`; homes need the control rule; `renew` only extends; notices MUST; never-slotted removal without rotation. |
| M2 Swift path losses | §15.3, §16.2, §16.3 | Freeze; slots for every slotted controller or stop; role, custody, operator and caveat mapping or stop; normative verifier. |
| M3 Replay | §12.3, §12.4, §13.4, §14 | Shared and atomic, 7,200 s, keyed with the acting key; recover-only can't call; `colophon.home.*` signers defined. Read-purpose replays return nothing. Every identical replay is `refused:replay`, not `refused:conflict`, to match the contract. |
| M4 Evaluation point | §12.3 step 4–5, §17.5 | Evaluated at S, with held removals applied; publish to every home. |
| M5 Revocation walk | §9.5, §11.5 | As required. |
| M6 Proposals | §11.6 | Clock rule; never final. |
| M7 0.3 incorporation | §11.8, §13.4, §14 | Exact section list; relay paths follow §13.4. |
| M8 Re-adding | §3.3, §8.3 | Allowed with new slots; vector. |
| L1 Draft-1 vectors | §D, implementation step 0 | Before freeze. |
| L2 Replay key, rate limit | §12.4 | Done. |
| L3 Flags, bytes after 37 | §4.3 | Done. |
| L4 Cross-account key reuse | §3.3 | SHOULD. |
| L5 Quorum above homes | §6.3 | `malformed`; no homes means calls are `unavailable`; hosts warn. |
| L6 History size | §2.4 | No cap; at least 1,048,576 entries supported. |
| L7 Dates, fractions, call protocol | §2.2, §12.3 | Done. |
| L8 HPKE oracle | §17.2 | Host only, registered prefix. |
| "What held" | — | Unchanged. |
| Vectors required before final | §21, candidate README | Engine-free ones produced; the rest named in §21 and made implementation step V1. |

### G.3 The eleven places two teams would have to guess

| Guess | Closed by |
| --- | --- |
| Fork handling and moving the high-water mark | §8.6, §13.3 |
| Succession freshness and uniqueness | §15.1 rules 1–3 |
| The revocation walk and what `kept` may contain | §9.5 |
| Controller re-add | §3.3 rule 3, §8.3 |
| Which seq calls are evaluated at | §12.3 steps 4–5 |
| Who may sign `colophon.home.*` | §14 |
| How relay and home share `{base}`, and history privacy | §13.4, §14 (`GET {base}` carries `home`) |
| Which 0.3 sections are normative | §11.8 table |
| Controller-call purposes | §12.3 step 7: the verifier configures them; recover-only never |
| Replay-store sharing | §12.4 |
| The Swift predecessor verifier outside Swift | §16.3, §17.2 |

### G.4 Second Opus review (of 9e90470)

| Finding | Settled in | How |
| --- | --- | --- |
| R1 no home, no delay | §6.4, §8.4, §18 | Stated; MUST warning; reference setup appoints a home before any recovery key |
| R2 calls by delayed or provisional keys | §12.3 step 5 | `refused:revoked`; vectors `call-by-delayed`, `call-by-provisional-after-until` |
| R3 primary home blocks recovery | §8.4 full recovery, §8.6 rule 2, §13.1, §6.3 | Any home stores and receipts recovery and cancel entries; home and primary changes are recovery-set triggers; the way out when homes are gone; the unrecoverable case stated |
| R4 receipts and cancels | §8.4, §13.1, §13.5 | Latest of `headQuorum` receipts; cancels under the ±300 s clock rule; attempt 2 and counter-recovery; delay protects authority, not data; security keys `recover` only |
| R5 removed keys fork forever | §8.6 rules 1 and 4 | Equivocation evidence; vector `removed-key-equivocation` |
| R6 `rotateRecovery` defeats rule 5 | §15.1 rule 5 | Genesis root and recovery identities also sign after any rotation; vectors `swift-rotate-recovery-*` |
| R7 Swift recovery addition signs F | §15.1 rule 6, §16.2, §16.3 | Successor activation before verified; refusal; home before F; vector `swift-recovery-added-freeze` |
| R8 entries after F | §15.1, §15.2 | `malformed` evidence; persistence; fresh-verifier rule |
| M-a missing triggers | §6.3, §8.4 | Policy classification table; every recover-key field |
| M-b recover-set swap | §15.1 rule 4 | Swap needs recovery consent; vectors `swift-webauthn-role-swap-*` |
| M-c data between snapshot and F | §15.3, §15.4 | Preflight, F, drain window, `migration.drain`, left-behind records shown |
| M-d no way back | §15.2, §16.2 | Stated irreversible |
| M-e where the predecessor is published | §15.1, §14 | Predecessor homes; successor homes for Swift at `{base}/predecessor/` |
| M-f strict DER | §16.3, §15.3, §21 | CryptoKit-observed acceptance; preflight; Swift WebAuthn vectors; dry run in §21 |
| M-g equality and malleability | §2.2, §8.6, §11.8, §14 | Body-byte equality; 0.3 §7.1 and §8.2 substitutions; vector `malleated-envelope` |
| M-h `memberRule: control` gaps | §8.4 | `endSessions` and `rekey` follow it |
| M-i provisional repeats, `until` | §6.1 | One at a time; never extended; confirmation by control rule; slots only after confirmation |
| M-j §11.8 gaps | §11.8, §9.5 | Paragraphs named by their opening words; layout 2 from genesis; `duplicateID`; kept invalid payloads; uncaveated; reducer inputs; batch acknowledgement; envelope bytes |
| M-k unbounded history | §2.4 | Portability floor; documented service limits; `unavailable` beyond them; owner warning |
| M-l receipt timing and paths | §13.5 | `received` ≥ `issued`; one file per home |
| Low: raw high-S | §4.2 | Restated |
| Low: links 1–8 vs depth | §12.2 | 1–4 |
| Low: redundant delayed exception | §12.3 step 5 | Replaced by a held recovery entry changing nothing |
| Low: QR `nA` | §7.3 | H still sends `nA` |
| Low: sign-only host rule | §17.3 | Host MUST |
| Low: native beta builds | §3.2 | MUST NOT share the production `rp` |
| Low: `handover` origins for carried-over keys | §15.1 | The genesis descriptor's |
| Low: new `agreement` for carried-over keys | §8.4 possession | Stated harmless |
| Low: `migration.view` | §15.4 | Defined |
| Low: L1 draft-1 vectors | Plan step V1 | Before freeze |
| §5 vectors without an engine | candidate README | Max-threshold rule, every trigger, receipts, calls by delayed and provisional keys, removed-key conflict, malleated envelope, Swift WebAuthn predecessors, `rotateRecovery`: all now exist. Still missing: future `issued` held, cancel by a recovery-added key, possession from a non-authority origin, two `resolve`s, quorum-2 stale call, `/5` predecessor (step V1) |
| §5 freeze condition | §21 | Dry run, security review and Galley alignment added; differential Swift corpus added |
| §6 Galley contract | §B.4 | Thirteen items listed for the contract |

### G.5 Second Codex review (of 9e90470)

| Finding | Settled in | How |
| --- | --- | --- |
| H1 delay timing and liveness | §8.4, §13.1, §13.5 | No-home delay stated as none (not backdatable, simply absent); receipts by `headQuorum` homes, latest counts; every home receipts recovery; full recovery when homes are gone. The two-homes-mandatory form was rejected (§F) |
| H2 narrow key freezes account | §8.6 | Evidence vs vouched fork vs no-home priority; no narrow key can freeze |
| H3 succession uniqueness | §15.1 | Named publication places; persistence; stated limit at quorum 1. Multi-home finality proof rejected (§F) |
| M1 indefinite cancel | §8.4 attempt 2 | Solo cancel works once; attempt 2 needs a counter-recovery |
| M2 missing policy triggers | §6.3 | Classification of every field: `primaryHome`, homes, `headQuorum`, raising `headMaxAge` and more |
| M3 provisional authority | §6.1 | Sponsors, one at a time, calls and services-only grants only |
| M4 holders | §6.1 | Who may set them, the key's co-signature, the honest statement |
| M5 at-most-once effects | §12.4 | CAS reservation with `pending` and `completed`; purpose in the key |
| M6 attacker-selected work | §2.4 | Documented limits, `unavailable` beyond them, floor every service supports |
| M7 legacy behaviour | §16.1, §16.3, §21 | 0.4-keys §2–§7 incorporated for the `/4` prefix; CryptoKit-observed acceptance; differential corpus in §21 |
| Low: PRF invariant | §3.2 | Stated as a security invariant |
| Low: no generic call purpose | §12.3 step 7 | Stated |
| Low: pairing encoding, one reveal, rate limit | §7.3 | Stated |
| Low: held recovery doesn't mutate state | §8.4, §12.3 | Stated |
| Low: migration is an assertion | §15.4 | Stated |
| Low: conformance self-consistency only | §21, README | Agreed; freeze waits for step V1 and two implementations |

### G.6 Places two teams would still guess (second Opus review, §4), closed

| Guess | Closed by |
| --- | --- |
| Equality of entries, records, heads | §2.2 |
| Initial layout of a `/5` account | §11.8 (layout 2 from genesis, no entry) |
| Where a Swift predecessor's history is fetched | §15.1, §14 |
| Entries after F; `resolve` after `successor` | §15.1, §15.2 (`malformed` evidence; no resolve) |
| Extending `until` | §6.1 (never) |
| Receipt paths for several homes | §13.5 |
| QR path's `nA` | §7.3 |
| Whose `authorityOrigins` govern carried-over keys | §15.1 (the genesis descriptor's) |
| "Canonical view" in `migration` | §15.4 |
| 0.3 "Fold order paragraphs" range, "uncaveated" | §11.8 |
| Kept record with `invalidPayload` | §9.5, §11.8 |
| What a service may do with a huge history | §2.4 |

### G.7 Third reviews (of 365f52b)

The architect adopted Codex3's pending-transition design. Revision 4 implements it and removes
the machinery it makes redundant.

| Finding | Settled in | How |
| --- | --- | --- |
| Codex3 H1 recovery starved by primary collisions | §8.6 rule 1, §8.7, §13.1 | Transitions are outside the sequence; every home receipts them; `activate` is ordered before ordinary entries; absolute bound of 7 days after due |
| Codex3 H2 control plus recovery key capture | §8.7 table | Every reducing change is pending and vetoable; vetoes need as many keys as signed; the owner with more keys wins (vector `row-thief-control-and-recovery`) |
| Codex3 H3 digest tie-break | §8.6 rule 3 | No digest ordering; without homes a conflict is a fork until a full-set `resolve` |
| Codex3 M4 full recovery vs approve-only rule | §8.7 full set | The separate rule is gone; a full-set transition is still bound by its change's rule (recovery adds only `approve` when `recoverThreshold` < `threshold`, a setting the owner chose) |
| Codex3 M5 provisional grants | §6.1 | Provisional controllers are removed. Approve-only keys are added immediately by `addThreshold` signers and grant like any `approve` key |
| Codex3 M6 succession activation | §15.1 | Successor homes receipt the genesis digest (§13.5 validity rule extended); veto object and window defined; F only after |
| Codex3 M7 replay states | §12.4 | `pending` → `completed(result, effect)` or `completed(result, none)`; every refusal completes; crash recovery by the idempotency record |
| Codex3 M8 loosening authentication | §8.4 table | Every loosening of any controller is pending (vetoable); recovery keys also need consent |
| Codex3 M9 CPU floor | §2.4 | 262,144 signature verifications; no time limit that refuses such a history |
| Codex3 lows | §8.7 table, §15.1, README | Lost recovery key needs consent (row 1); the Swift post-final vector fixed; iOS and visionOS stated unverified |
| Opus3 H1 raising `threshold` | §8.4 | Raising `threshold` is pending with recovery-set consent; vector `t-raise-threshold-no-consent` |
| Opus3 H2 filling the keyring | §6.2 | Immediate entries stop at 56; vectors `i-headroom-56`, `i-headroom-57` |
| Opus3 H3 stranded slots | §8.3 | Vault changes are pending; the new slot set must name every slotted controller; changing the vault while a recover key has a slot needs recovery consent |
| Opus3 rule 5 unmeetable | §15.1 | Replaced: current root and recovery kit (as the app holds them after `protect()`, `recover()`, `rotateRecovery()`), plus the veto window; vector `swift-rotate-recovery` now verified |
| Opus3 two inverted vectors | candidate | `call-by-provisional` and `call-by-delayed` are gone with their rules; replaced by `call-by-pending-addition` (refused) and `call-by-pending-removal` (ok) |
| Opus3 DER probe on `s` | §16.3, README | Extended to `r`, `s` and high `s`; the unpadded form is refused, not accepted; revision 3's claim corrected |

**Kept from the old machinery, and why:**

- **Receipts, latest of `headQuorum`.** That is how the delay gets a time nobody backdates.
- **The recovery-set consent list.** A veto needs someone awake. Consent stops a thief with one
  control key from even proposing to touch recovery while the owner is away.
- **The recovery rule's approve-only limit when `recoverThreshold` < `threshold`.** It is the
  owner's own setting, and a threshold raise can no longer be forced on them.
- **The fork rule for homes that vouch for both branches.** Transitions can't create such forks,
  but ordinary immediate entries can when homes misbehave.
- **`resolve`**, now as a transition.

**Rejected:**

- **Codex3's "require two recovery controllers without a home"**: rejected again. The owner's
  one-key default stands, and the spec says plainly that an account without a home has no theft
  safety.
- **Making `approve`-only additions pending:** rejected. The architect classed them immediate. A
  company that wants otherwise sets `addThreshold` to `threshold` and `memberRule` to `control`.

### G.8 Fourth reviews (of 4032d44)

| Finding | Settled in |
| --- | --- |
| Opus4 H1 anchor decides rule, delay, homes | §8.7 "Evaluation point" |
| Opus4 H2 tightening another key | §8.4 `keyring` row and pending table |
| Opus4 H3 slot added under a removal | §8.3 "A vault change" |
| Opus4 H4 history bloat | §13.1 rate; §8.2 one epoch per namespace |
| Opus4 H5 recover keys can't read | §12.3 step 5; §13.4 |
| Opus4 H6 racing `activate` | §8.7 "Activation" (determined bytes); §8.6 rule 1 |
| Opus4 H7 receipts and signer set in envelopes | §8.7 `signers`, due time |
| Opus4 H8 `activate` erasing covered entries | §8.6 rule 1 |
| Opus4 H9 full set | §8.7 "Full set"; §H rows |
| Opus4 H10 Swift receipts malformed | §13.5; vectors regenerated |
| Opus4 M1 suspension | §8.7 "Suspension"; §12.3 |
| Opus4 M2 backdating home at quorum 1 | §13.1 (store `activate` only if receipted or seen a delay earlier); §18; §G.7's claim "nobody backdates" corrected: at quorum 1 a hostile home can backdate |
| Opus4 M3 one home down | §18 (two homes); §6.4 |
| Opus4 M4 transitions and vetoes as authority signatures | §4.3; §8.7 |
| Opus4 M5 notices | §17.5; §21 item 7 |
| Opus4 M6 succession vetoers | §15.1 |
| Opus4 M7 `layout`, `migration`, unknown kinds | §8.4; §13.1 stores only `ok` |
| Opus4 M8 equal sides | §8.7 "Escalation"; §H |
| Opus4 M9 headroom wording, slots | §6.2 |
| Opus4 M10 replay reservation | §12.4 |
| Opus4 M11 members of a removed key | §17.5 |
| Opus4 lows | 7-day bound by home clock (§13.1); relabel display (§6.1); full-set rationale (§8.7); root-only hand-over (§15.1); premature freeze (§15.1, §16.2); `until` gone from the plan; floor and background verification (§2.4); approve key with its slot in one entry (§8.4); 300 s at quorum 2 (spec §17.5 "Quorum 2", added in revision 6) |
| Opus4 §E 17 guesses | evaluation state; re-checks; due-time receipts; signer set; ordering; rule-1 condition; full set; delta semantics; slot rebasing; "who can't propose" (removed: a removed signer voids at activation); mutual removal tie (equal due time to the second voids both, via §8.6 rule 1 ordering then void); 7-day bound; veto signer currency (state before the `vetoed` entry); v(u) after re-add (kept); headroom; Swift veto recording; losing-branch anchor (void). All in §8.6–§8.7, §6.2, §15.1 |
| Opus4 cuts | Who-wins table moved here (§H); probe narrative cut; §17.2, §15.3, §15.4, §16.2 shortened. The spec is 1,724 lines (from 1,771). `countBy: holders` kept: the owner's company case needs it, and counting units make it uniform |
| Codex4 High 1 immediate takeover | §8.4. Approve and sign additions and member grants stay immediate (the architect's earlier decision); one key's worst use of each is tabulated with its bound |
| Codex4 High 2 composite transitions | §8.7 `change` |
| Codex4 High 3 veto vs accepted activation | §8.7 "Finality" and veto quorum: a veto needs `headQuorum` receipts; finality needs every home. The two certificates intersect |
| Codex4 High 4 escalation reset | §8.7 "Escalation" |
| Codex4 High 5 four-key table | §H uses the real reference; 1+1 against 1+1 is a stall, stated; hostile sole home plus one recovery key is a loss, stated |
| Codex4 Mediums | counting units (§6.1); conditional bounds (§H); succession attempts (§15.1); external-object limits and the all-signature floor (§2.4, §8.7); replay `abandoned` (§12.4) |
| Codex4 low: auto-suspension | Rejected as automatic. Suspension is an explicit entry by a signer of a pending removal, and costs one veto if abused |

### G.9 Fifth reviews (of a1decc6) and the engine builder's notes

| Finding | Settled in |
| --- | --- |
| Opus5 H1 replayable `activate`/`vetoed`; uncheckable timeliness | §8.7 "Recording entries" (once only, `transitionReceipts`, 7-day bound against the due time), v(u) over distinct transitions |
| Opus5 H2 final not final | §8.7 "Finality": never displaced, evidence against the intersecting home, provisional additions count for nothing, rollback removes the suffix. **Changed:** finality uses the homes current *before* the activation (Codex5's snapshot), not after: with the "after" set, a thief holding M and K1 at quorum 1 revokes the honest home, which holds the owner's valid veto, and the hostile home alone makes the activation final. A full set, which can't be vetoed, uses the homes after it. **Liveness corrected:** with one of two homes gone for good, removals still take effect at D + 300 s; additions need one full-set transition revoking the gone home (both security keys at the reference), final as soon as the remaining home covers it. For that, the recovery rule may now change homes (§8.4) |
| Opus5 H3 due time depends on receipts held | §8.7 "Receipts and due time" (`issued` + 300 s + delay; forwarding; receipt choice by lowest home ID); §8.6 rule 1 (same-transition recordings; signed entries go back to their signers). **Added:** the veto deadline is 300 s before the due time, so homes can exchange veto receipts before anyone appends |
| Opus5 H4 suspension | §8.7 "Suspension"; §12.3 step 5; §13.4; homes don't receipt a void transition |
| Opus5 H5 rate limit | §6.3 `rate`, §13.1 "Rate", §8.4 four per addition. `suspend` counts toward the signer limit only (not exempt), so it can't be used to flood |
| Opus5 M1 `keep` | §8.7 delta semantics; vector `t-keep-removes-unknown-key` |
| Opus5 M2 storage after D | §13.1 "Transitions"; row 13 restated |
| Opus5 M3 vault-change `activate` | §8.3: `previousVault` moved into the transition and the `activate` made determined, which also closes Codex5 High 3; epochs come from a `rekey` the seed holder appends |
| Opus5 M4 schemas, sizes | §8.2, §2.4. The reviewer's 917,504-byte transition body doesn't fit once base64-embedded (×4/3), so the envelopes are bounded instead: transition 655,360, veto 98,304, receipt 2,048 |
| Opus5 M5 succession | §15.1 steps 2–5; "Competing attempts"; §16.3 |
| Opus5 M6 composite | §8.7 "Composite rule" |
| Opus5 M7 table | §H rows 4, 5, 9, 10, 12, 13 corrected; rows 17–21 added; vectors fixed (rows 2, 9, 10 change the vault; row 13 uses the determined bytes; `t-suspend` family cites a valid transition; `t-anchor-before-first-home` discriminates; `t-activate-identical-bytes` has both byte sets) |
| Opus5 M8 never-due `activate` | §8.5 step 3 |
| Opus5 lows | §15.4 JSON; §F rewritten; plan steps 2, 8, 9; §17.5 "Quorum 2"; removal follow-up lists planted controllers; slot rebuilding (§8.3); full set carries no receipts (§8.7); rate as a policy field |
| Opus5 Q3 reference | §18 split into new accounts and upgrades; the host paragraph; phone-only offer; §16.2 roles carried over |
| Opus5 Q6 disclosure before the window | §15.3 one sentence |
| Opus5 Q8 engine-free statements | 33 new or rewritten vectors (README) |
| Opus5 Q9 cuts | Guide: §8.4 worst-use column, §6.4 wording, §3.2 explanation, §17.1–§17.2, §18 "what this protects", §20 list, §22 log (about 110 lines). The spec still grew, to 1,855 lines, because of the text above |
| Codex5 High 1 finality | As Opus5 H2, using Codex5's snapshot; the full set is the "unvetoable override" |
| Codex5 High 2 rollback | §8.7: additions sign nothing until final, so rollback is the suffix only |
| Codex5 High 3 vault payload | §8.3 (payload in the transition) |
| Codex5 High 4 Swift veto recording | §15.1 step 4: `successionVetoed` with its own schema, descriptor lookup, origin and UV rule, receipt choice, ordering and coverage |
| Codex5 Medium 5 composite | §8.7 |
| Codex5 Medium 6 provisional additions | §8.7 "Until final"; §12.3 step 5 for members and homes |
| Codex5 Medium 7 receipt choice, persisted state | §8.7 "Choosing receipts"; §17.2 |
| Codex5 Medium 8 rate | §13.1 |
| Codex5 Medium 9 replay retention 7,200 vs 7,201 s | **Not changed this round:** outside the coordinator's list and inside the replay store the engine builder is implementing. Recommended for the next revision: retain 7,201 s |
| Codex5 Medium 10 pending-object paths | **Deferred:** §14 still defines no paths for transitions, vetoes and receipts outside the history; §17.5 polling needs them. Next revision |
| Codex5 extra losing row | §H row 21 |
| Builder 1 replay timing | §12.3 step 3 (read-only look-up), §12.4 (reservation after step 8): the builder's reading |
| Builder 2 error order | §1: one order, fields checked when a step reads them |
| Builder 3 unknown key form | §1: `newerFormat` (the builder's reading), with the reason |
| Builder 4 unknown condition operator | §10.4: three-valued (unknown, `not` unknown is unknown); the builder's "true" would make `not` of it false |
| Builder 5 path segments | §10.4: count includes `args` (the builder's reading) |
| Builder 6 printable | §2.2: 0x21–0x7E |
| Builder 7 year 0000 | §2.2: refused |
| Builder 8 oversized `clientData` | §2.4: `malformed` everywhere |
| Builder 9 link times | §12.1, §12.3 steps 1 and 6 (the builder's reading) |
| Builder 10 link to a principal | §12.3 steps 1 and 6: `malformed` |
| Builder 11 assertion mismatch | §12.2 (the builder's reading) |
| Builder 12 unknown account | §12.3 step 4: `unavailable` |
| Builder 13 which policy | §12.3 steps 4–5 (the builder's reading) |
| Builder 14 controller at S and latest | §12.3 step 5: both (the builder's reading) |
| Builder 15 member expiry | §12.3 step 5: verifier's clock, inclusive |
| Builder 16 future head | §13.3: `unavailable` |
| Builder 17 renew without expiry | §9.4: `malformed` |
| Builder 18 `revoke.heads` | §9.5: `{namespace, digest}` objects |
| Builder 19 `shares`, `epochs` | §8.2: §11.1 epoch objects |
| Builder 20 coverage direction | §9.2: granted ⊆ requested |
| Builder 21 `serves` values | §10.1 |
| Builder 22 `null` in `eq`/`in` | §10.4: allowed |
| Builder 23 home and history reads | §12.3 step 7: a home always accepts its `colophon.*` purposes |
| Builder 24 Swift leniency | §16.3: none; zero `r`/`s` refused |
| Builder 25 genesis possession | §8.4: the primary signature is the proof |
| Builder 26 per-link order | §12.3 step 6 (the builder's reading) |
| Builder 27 homes and members not final | §8.7 "Until final"; §12.3 step 5; §13.1 |
| Builder 28 floor | §2.4: binds services; a core MAY count |
| Builder vectors | `calls/one-link` now carries the condition (`ok`); `copied-link` then reaches the acting-key check (`badSignature`); `account/` appoints its home by a transition and its determined `activate`; `outside-window` names step 4 |
| Builder plan | Plan: Step 0 heading; Step 1 is a new module beside 0.4 |

## H. Theft and loss, worked through

**Reference person:** a Mac device key M, a phone device key Ph and a synced passkey P (all
`control`), two security keys K1 and K2 (`recover` only, kept apart), two homes at `headQuorum` 1,
D = 72 h.
- A "unit" is a key.
- A transition is due D + 300 s after its `issued`; vetoes count until D after it.
- Every bound assumes at least one honest, reachable home, and hosts that poll as §17.5 requires.
- With a hostile or unavailable required home, no bound exists.

| # | Scenario | What happens | Outcome |
| --- | --- | --- | --- |
| 1 | Owner lost one key | The owner proposes removing it with all remaining keys (two or more units, so a single thief key can't veto), with a vault change if it had a slot. | Owner wins after D + 300 s |
| 2 | Thief has the Mac key M | The owner vetoes each thief proposal with one key; then M can't propose alone. The owner proposes removing M with Ph and P, with a vault change (M holds a slot), and suspends M. | Owner wins after D + 300 s; suspended M can't call meanwhile |
| 3 | Thief suspends an owner key first | M proposes removing Ph and suspends Ph. Ph vetoes its own removal (one against one), ending the suspension. M can't propose alone again. | Owner wins |
| 4 | Thief has the phone (Ph and P) | K1 and K2 are the full recovery set: with `keep: [M]` they remove every other non-recover key at once. | Owner wins at once |
| 5 | Phone-only owner (no M), phone stolen | Ph and P are every control key: the thief can add his own control keys at once, but nothing needing consent. Both security keys, with `keep`, remove every non-recover key the owner doesn't name, including keys added after the owner looked. | Owner wins at once with both security keys; with one, stall until the second is retrieved. Hence §18's offer of a security key with `control` |
| 6 | Thief has one recovery key K1 | The owner vetoes; K1 can't propose alone again. The owner removes K1 with a control key and K2. | Owner wins after D + 300 s; the thief reads the vault at once if K1 has a slot and he has its PIN |
| 7 | Thief has M and K1; owner has Ph, P and K2 | The owner signs the removal with three units, which two can't veto. | Owner wins after D + 300 s |
| 8 | Equal units (one control plus one recovery on each side) | Neither completes a transition. Both keep immediate powers, subject to suspension and the rate limit. | Stall until one side obtains another key |
| 9 | Owner has both recovery keys and no device | K1 or K2 reads the history. K1 and K2 sign a full recovery set: `keep: []`, a new device key, a new vault. | Back in at once; old data is reachable only if a recovery key had a slot |
| 10 | Burglar takes both recovery keys | The same, by the burglar. | Burglar wins at once. Closed by keeping the keys apart, or `recoverThreshold` 2 with three keys |
| 11 | Honest mistake | The found phone vetoes. | Nothing changes |
| 12 | One home down | The other home receipts and vetoes; transitions fall due; removals apply. Additions stay provisional until the down home covers them. If it is gone for good, one full-set transition (K1 and K2) revokes it and adds keys, final once the remaining home covers it. | Removals proceed; new keys wait, or a full set revokes the gone home |
| 13 | One hostile home (quorum 1) and one stolen key | It receipts a backdated transition and appends the determined `activate`. The honest home never saw it within 300 s of its `issued` and refuses it for ever. | A fork the owner must `resolve`; verifiers that follow only the hostile home apply the thief's removals. **Not safe at quorum 1.** Closed by three homes at quorum 2 |
| 14 | Hostile sole home and one control or recovery key | The home receipts the thief's transitions and hides vetoes. | **Thief wins** |
| 15 | Sole device stolen, no other control key | As row 5. The owner learns of the thief's transitions the next time a recovery key is used with any host (§17.5). | As row 5 |
| 16 | No home | Nothing waits. | Whoever holds keys meeting the rule, consent and thresholds wins at once |
| 17 | Thief has the phone and one security key (Ph, P, K1) | Three units against the owner's two (M, K2): the owner's veto is too few. | **Thief wins after D + 300 s** |
| 18 | Burglary of the place holding M, the phone and K1 | Four units against one. | **Thief wins after D + 300 s** |
| 19 | Thief has M and the phone (every control key) | He makes control-only changes at once (adding keys), nothing needing consent. Both security keys with `keep` remove all of it at once. | Owner wins at once with both security keys |
| 20 | Owner doesn't look within the delay | Nobody vetoes. | **A thief with one key wins after D + 300 s.** Every other row assumes hosts poll (§17.5) |
| 21 | Two homes at quorum 1; the honest one is down for the whole delay; the reachable one is hostile; the thief has one key | The hostile home receipts the thief's transition and drops the owner's veto. | **Thief wins** (rows 12–14 combined) |
