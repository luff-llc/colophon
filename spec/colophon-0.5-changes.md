# Colophon 0.5: changes from 0.4, upgrade paths, review answers and deferred items

**Status:** companion to [colophon-0.5.md](colophon-0.5.md), revision 3, 2026-11-11. Section
numbers without a prefix are 0.5's. "0.4" means [colophon-0.4-keys.md](colophon-0.4-keys.md).
"Galley draft" is Galley's `docs/spec/colophon-0.5-draft.md` (draft 2). "The contract" is
Galley's `contracts/identity/one-identity.md` on branch `one-identity-contract` (head 172fe8f).
"Codex N" and "H/M/L N" are the two reviews of revision 1 (152d991), mapped in §G.1–§G.3.
"Opus R/M" and "Codex2 H/M" are the two reviews of revision 2 (9e90470), mapped in §G.4–§G.5.

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

| Fork | Chosen | Rejected, and why |
| --- | --- | --- |
| 0.4 → 0.5 | In place | Clean copy: loses members and IDs for nothing. |
| Swift → 0.5 | Clean copy with a frozen predecessor, a verified hand-over and a migration entry | Teaching every 0.5 verifier to read Swift content forever. Only the authority part of §16.3 is needed, and only for succession. |
| Succession anchor | The predecessor's single final entry, at `head.seq + 1` | The reviewer's text puts the final entry at `head`. That is a cycle: the final entry names the genesis's digest, and the genesis would name the final entry's. The one-entry offset gives the same uniqueness and freshness. |
| Recovery default | Any one recovery key, plus a 72 h delay, receipts and a one-key cancel | Codex 2's `max(2, threshold)` recovery signers. It overrides the owner's stated default; the delay makes one-key recovery safe instead. |
| What a delay blocks | Every signature by the recovery-added key until the delay ends | H2's narrower list (only weakening entries). The narrow list means home-side judgement about which entries weaken; the broad rule is deterministic. A recovery key with `approve` (the reference default) still admits apps during the delay. |
| Who attests time | Any current home's receipt | Only the primary (one point of failure for recovery), or `issued` alone (backdatable). |
| `issued` at homes | Refused more than 60 s ahead; recovery entries refused more than 300 s either way | H2's 60 s in both directions for every entry. That would refuse honest entries signed offline and uploaded later. |
| Below-threshold additions | Provisional: approve only, no slot, `until` ≤ 30 days | Codex 1's "no role at all". That makes the one-approval add useless; approve-only with an expiry bounds it. |
| Fork resolution | `resolve` under the control and recovery-set rules of the pre-fork keyring | First-seen wins. That diverges forever across verifiers. |
| PRF exposure | Stated, plus deployment rules, plus combined slots as a setting | Codex 3's mandatory combined slot or `vaultOrigins` allowlist. Browsers, not the account, decide which origins get PRF; an allowlist in the account can't be enforced. |
| Freshness | Primary home plus `headQuorum`, stated limits | Codex 5's pinned witness or checkpoint. It is a new trust root; left as an extension. |
| Pairing | Commit-then-reveal SAS, or QR | A PAKE: no allowlisted implementation, and SAS has the same one-in-a-million bound per attempt. |
| Epoch and slot labels | Unchanged | `/5` labels: no gain, double code. |
| Recovery without a home | Allowed, with no delay, and a MUST warning; the reference setup appoints a home before adding any recovery key | Codex2 H1's "two recovery holders when no witness". It would override the owner's one-key default. The owner can still choose `recoverThreshold` 2 |
| Delay witness | Receipts from `headQuorum` homes, latest counts; any home stores recovery and cancel entries | Codex2 H1's mandatory two independent homes. `headQuorum` 2 gives exactly that as a setting; companies default to it |
| Repeated cancel | Attempt 2: twice the delay, cancellable only with a counter-recovery; attempt-2 additions removable only under the recovery-set rule | Codex2 M1's "solo cancel once per epoch, then final after a dispute period". Attempt 2 is the same idea with a deterministic trigger. The full-quorum override the architect suggested is kept as "full recovery" for the homes-gone case |
| Fork classification | Evidence when heads cover one branch; recovery at a non-primary home yields to the primary; vouched forks need `resolve`; no-home conflicts by rule strength, then digest | Codex2 H2's "finality certificate from a home quorum" for every account. This needs homes for everyone; rule 4 covers accounts without homes and can never freeze |
| Succession finality | Publication at named places (the predecessor's homes; the successor's homes for Swift), persistence, refusal for recovery-added signers | Codex2 H3's fixed multi-home finality proof with a fresh challenge. It is a new protocol; `headQuorum` ≥ 2 on the predecessor gives the multi-home property as a setting, and the limit at quorum 1 is stated |
| Holders | Labels attested by the controllers; the key co-signs its own label; recovery-set rule for recover keys | Codex2 M4's "cryptographically bound stable principal". 0.5 has no identity layer for people, and inventing one would be a second account system |
| Provisional authority | Calls and services-only grants; bound to sponsors; one at a time; `until` never extended | Codex2 M3's "no grants at all before confirmation". Services-only grants keep the one-approval new-platform case useful; records grants are refused |
| History bound | Portability floor 65,536 entries and 256 MiB; services MAY set higher limits and answer `unavailable` beyond them | Codex2 M6's "resumable from an authenticated checkpoint". Resumption is from the verifier's own persisted state; a signed checkpoint is still refused (R4) |
| Swift DER leniency | Exactly what CryptoKit accepted on macOS 27, probed; duplicate `clientData` refused, with the preflight to find any | Strict §4.3 grammar for predecessors, which could make real libraries unmigratable (Opus M-f) |

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
