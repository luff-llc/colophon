# Colophon 0.5: changes from 0.4, upgrade paths, review answers and deferred items

**Status:** companion to [colophon-0.5.md](colophon-0.5.md), revision 2, 2026-11-11. Section
numbers without a prefix are 0.5's. "0.4" means [colophon-0.4-keys.md](colophon-0.4-keys.md).
"Galley draft" is Galley's `docs/spec/colophon-0.5-draft.md` (draft 2). "The contract" is
Galley's `contracts/identity/one-identity.md` on branch `one-identity-contract` (head 172fe8f).
"Codex N" and "H/M/L N" are the two reviews of revision 1 (152d991). They map to sections in §G.

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

### B.4 Where the contract still assumes what 0.5 does not provide

1. **Accounts as controllers** (contract 0.1, 1.4, 7.1): not in 0.5 (§C). A company's controllers
   are its people's keys, with `holder` and `countBy: holders`.
2. **A verifier stricter than Colophon on ceremony origins for authority** (contract 4.6 applies
   it to calls only, which is allowed). For authority entries, no verifier may be stricter (§4.3,
   §8.5).
3. **The contract's §11** already uses the succession path (§16.2) for people with Swift
   libraries. It must add these, which 0.5 now requires:
   - the freezing `layout` entry;
   - possession proofs for every controller that is not carried over;
   - for a root library, the recovery identity's signature;
   - for a Two Keys library whose `recoverThreshold` is lowered, recover signers in `handover`;
   - the `migration` entry, which any principal move (contract §7.5) MUST require.

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
