# Colophon 0.5: changes from 0.4, upgrade paths and deferred items

**Status:** companion to the final candidate [colophon-0.5.md](colophon-0.5.md), 2026-11-11.
Section numbers without a prefix are 0.5's. "0.4" means [colophon-0.4-keys.md](colophon-0.4-keys.md)
unless stated. "Galley draft" means `docs/spec/colophon-0.5-draft.md` (draft 2) in
luff-llc/galley; "the contract" means Galley's `contracts/identity/one-identity.md` (PR #64,
`a644a7b`).

## What existing keyrings actually are

This was checked in code, not only in documents.

- **Mike's library, used by Taupe and Marginalia, is not a 0.4 library.** The shipped apps
  run Marginalia's Swift `ColophonAuthority` (Marginalia `origin/main` `c8280332`,
  `packages/Colophon/Sources/ColophonAuthority`): a 0.1 genesis with a root and a recovery
  identity, optionally followed by a root-signed `keyring` entry that adopts controllers
  (`AuthorityState.swift`, "The root-signed `keyring` entry is the upgrade"). Its library ID is
  the first 32 hex characters of SHA-256 of the first body (`AuthorityState.swift:98`). Its
  keyring rule is in `verifyKeyringChange`; its WebAuthn check (`Controller.swift`) allows
  `https://<rp>` or a subdomain and has no origin allowlist. Its slot labels are
  `colophon/vault-prf/1` and friends (`VaultSlot.swift`), different from 0.4's.
- `colophon/docs/handoff-keys-04.md` ("Not verified here") records that the clean copy of Mike's
  library to 0.4 was never done and the app cutover never started. I found no 0.4 library
  outside test fixtures and the playground. I could not inspect Mike's devices, so whether his
  library has adopted a keyring, and which keys it holds, is unverified; the contract (§14)
  reads `LibrarySessionKeyring.swift:207` as giving the shipped passkey `approve` + `recover`.
- So there are two upgrade paths, both specified: **in place from 0.4** (§16.1), for any
  library made with the 0.4.0 SDK; and **succession from the Swift keyring authority**
  (§16.2), which is Mike's real path.

## A. Changes from 0.4

"Breaking" means a 0.4 reader cannot read what a 0.5 writer produces. In every case a 0.4
reader stops with `newerFormat` (update required) at the account's `upgrade` entry and never
reaches the new bytes: this was run against the released 0.4 engine
(`conformance/0.5/candidate/README.md`).

| # | Change | Why | Breaking | Upgrade path for an existing 0.4 library |
| --- | --- | --- | --- | --- |
| 1 | **Account IDs are 64 hex** (§5.1), text form `colophon:<id>` | IDs are now used across accounts and by services that have never seen the account; 128 bits invites deliberate collisions between accounts an attacker makes. | Yes | None needed: the ID is the full digest of the same genesis body, so the old ID is its prefix. The `upgrade` entry states the full ID, signed by the control quorum (§16.1). Old records keep binding the 32-hex ID and stay valid. |
| 2 | **`upgrade` entry** (a 0.4-format entry of a new kind) and the `/5` authority protocol after it (§8.1, §16.1) | One signed, checkable step that keeps the same account, keys, vault, slots, epochs, members and records, and makes 0.4 readers stop safely by 0.4's own rule. | Yes, by design | Append it once, after every app is on 0.5. No passkey ceremony, no rotation, no new account. |
| 3 | **`addThreshold` and the add rule** (§6.2, §8.4) | Mike: adding a passkey on a new platform must be one approval. Under 0.4 it needed the full control quorum. The add rule only adds, and caps the roles it can add so a single key never manufactures `control` or `recover` above the person's thresholds. | Yes (new keyring field) | Chosen in the `upgrade` keyring; host default 1. With 0.4's typical `threshold` 1, nothing a person can do changes; with `threshold` 2, one key can now add approve-only keys, which the person sees in the upgrade and in every notice (§17.5). |
| 4 | **Account `policy`** (`headMaxAge`, `headQuorum`, `callWindow`, `linkMaxAge`, `history`) (§6.3, §18) | Policy is configuration with a default, a range and a holder of the right to change it (D78). These are the values that differ between a careful company and a casual person. | Yes | Set in the `upgrade` keyring; defaults in §18. |
| 5 | **Web origins in `origins`, and `authorityOrigins`** (§3.1, §4.3) | WebAuthn Related Origin Requests are real and the owner, not the relying party, should consent to them (contract R9). `authorityOrigins` lets an owner keep account changes on a named ceremony origin (contract R8). | Yes (new values) | Optional; absent keeps 0.4 behaviour exactly. Changing them is a control-rule change without rotation. |
| 6 | **The verifier's location never enters verification**, and verifiers may not be stricter than the spec for authority entries (§4.3, §8.5) | Staging and production are two readers of the same data; if one refuses an entry the other accepts, they hold different histories. | No | — |
| 7 | **Grants carry `terms`**, not 0.4's closed `grant` object (§9.2, §10) | Per-namespace access (0.3 couldn't grant read here and write there), a `propose` level (D25), operation-kind limits, conditions (D39), grants to systems outside the account (`services`, contract R3), link depth and homes (`serves`). | Yes | Existing grants convert mechanically (§16.1); members keep their IDs and keys. |
| 8 | **Membership requests are `colophon/request/5`** and ask for terms; the pairing code uses the 64-hex ID (§9.1) | Requests must name the account by its full ID and ask for the new terms. Member `kind` is kept, not replaced by terms as the Galley draft proposed, because AI attribution is signed fact about the key, not a permission. | Yes | Existing requests are historical evidence inside existing grants; new members use `/5`. |
| 9 | **`renew`** (§9.4) | Agents get seven-day access by default and renew it; 0.3/0.4 required a new key and a new grant each time. | Additive | — |
| 10 | **`revoke` keeps by author chain** (`heads`) as well as exact digests (`kept`); field `memberID` is now `member` (§9.5, §11.2) | A digest per kept record makes revoking a busy device a multi-megabyte entry. An author chain lets one digest per namespace keep a whole prefix without reopening backdating (the attack review's P0-01): a forged record is not an ancestor of the named head. | Yes | `/3` records keep exact digests; `/5` records use chains. |
| 11 | **Operation header `/5`**: `account` (64 hex), `level`, `previous` (§11.2) | Full ID, proposals, author chains. | Yes | `/3` records stay valid if they cite authority before the upgrade (§11.5). |
| 12 | **Proposals, `colophon.accept` and `colophon.decline`** (§11.6) | D25: write either as a proposal or directly. Resolution is first-valid in fold order, folded once (attack review P2-17). | Additive | — |
| 13 | **Links and calls** (§12) | Short sign-ins and agent sessions as signed delegation (D38, D73), and one signed shape for "this key acts for this account at this system" (sign-in, API calls). Verification order puts possession before any fetch and never yields `newerFormat` before authentication (attack review P1-10); the acting key must be the chain's last key (draft-2 correction 1). | Additive | — |
| 14 | **Session numbers and `endSessions`** (§9.6) | D38: end every session of a member at once. A member may end its own sessions. | Additive | Session numbers start at 0. |
| 15 | **Homes and heads** (§13, §14) | Services need a fresh, signed statement of the latest history, monotonic per verifier (attack review P1-11), from one or several homes (contract R5). | Additive | Appoint a home by grant under the control rule. |
| 16 | **Succession**: `predecessor` + `handover` on genesis, and `successor` (§15) | Identifier changes need a signed hand-over that any verifier can follow. Replaces 0.4's display-only `importedFrom`. | Yes (`importedFrom` removed) | Used for the Swift path (§16.2) and any later move. |
| 17 | **Genesis may declare no namespaces**; then there is no seq-2 rekey (§8.2) | A company or identity-only account has keys and grants but no data yet. | Additive | — |
| 18 | **Bounds**: controllers ≤ 64, slots ≤ 256, body sizes (§2.4, §6.2) | Bounded parsing before allocation. | Yes in principle | No real 0.4 keyring is near them. |
| 19 | **Seed transfer to a new device** (§7.3) | Adding a passkey on a platform with no existing controller needs the seed there to build its slot; 0.4 had no way. | Additive | — |
| 20 | **Vault seals for other formats** (§17.2) | Backups to the vault (contract R10) without exporting the seed or offering a raw ECDH oracle on the key that opens every epoch. | Additive | — |
| 21 | **All signed bodies are canonical JSON objects**; 0.5 readers refuse non-canonical base64 (§2.1, §2.2) | Contract R7 (no Colophon body can be mistaken for a LUFF signed body); one spelling per value (W1 finding 2). | Yes for `/5` | Older bodies are verified as their versions required. |

Unchanged and restated in full: strict parsing, key descriptors, one key one principal (per
account), private-key work in the host, COSE, envelopes, `raw` and `webauthn` checks, controllers
and roles, thresholds, vault, slots and their labels, PRF rules, rotation, the control and
recovery rules, verification order, import grants, epochs and their HPKE label, the operation ID,
fold order, clocks and admission.

## B. Galley's requirements (contract §13)

| Req | Settled? | Where | Notes |
| --- | --- | --- | --- |
| R1 verifier output | Yes | §17.2 | Adds the legacy ID, kind and label, renewal sequences, session numbers, and verified predecessor or successor. Incremental verification from a persisted state is allowed. |
| R2 standalone WebAuthn check | Yes | §17.2, §19 | Outcome name settled: `badSignature`, with a diagnostic naming the failed check. |
| R3 terms for an outside resource | Yes, differently | §10.1 `services` | An entry names an `audience` (URL or URN, with path, so a Galley instance and scope fit) and its purposes, with narrowing (§10.3). **No `environments` term:** an environment is an audience. A grant to `https://projects.luff.works/…` does not reach `https://projects.toolsperson.com/…` unless it names it, and it can give staging only read purposes. A separate environment vocabulary would put deployment names into the account's signed data, which the principles rule out. |
| R4 signed checkpoint | **No, deliberately** | §17.2, changes §C | A checkpoint signed by the account's own controllers can't be checked without the history that says who the controllers were; one signed by a home makes the home a trust root. Instead: verifiers persist verified state and fetch only `after` their high-water mark (§14); sessions never enter the history; author chains keep revocations small. Galley's 256-entry, 1 MiB proof cap is Galley's choice: a person adding an agent a week and renewing it reaches 256 entries in roughly two to three years, so the contract should let a proof start from a sequence the verifier already holds. |
| R5 several homes | Yes | §6.3 `headQuorum`, §13.3 | Account policy, default 1, range 1–8. Lower `seq` is behind, divergence is a fork. |
| R6 reading history | Yes, differently | §13.4 | Purpose `colophon.history.read` at the home's audience, plus `policy.history` (`members` default, or `public`). Not a namespace, because the history isn't a namespace's records. |
| R7 bodies stay JSON | Yes | §2.1 | Every signed body's first byte is `{`; PRF ceremonies sign random challenges (§7.2). |
| R8 origin pin for authority | Yes | §3.1, §4.3 `authorityOrigins` | Limit stated plainly: it can't separate a native app and a web page that report the same origin. The real mitigation is operational: serve no script at the bare `rp` origin and run authority ceremonies on a dedicated minimal origin that is the only one listed. Whether Apple native assertions carry `https://<rp>` is unconfirmed (contract §14). |
| R9 exact `https://` origins | Yes | §3.1 | Owner consent recorded in the descriptor; absent by default. |
| R10 vault key agreement | Yes, differently | §17.2 | HPKE open with a non-`colophon/` `info`, not raw ECDH. A raw ECDH oracle on the vault key would let any caller open every epoch seal. Galley's backup format must use HPKE (RFC 9180, the §11.1 suite) with its own `info` for the vault recipient. |
| R11 `user.id` | Yes | §17.4 | Account ID when the account exists; 32 random bytes when the credential is made before the account (a passkey in its own genesis can't contain the digest of that genesis). Never relied on. |
| R12 head body | Yes | §13.2 | `{protocol, account, authority:{seq,digest}, issued, by}`, either 0.3 date form. |
| R13 home in the first upload | Yes | §13.1, `POST {base}/authority` §14 | A genesis plus appointing grants in one batch. |

**Where the contract assumes what 0.5 does not provide:**

1. **Accounts as controllers** (contract §0 rule 3, §0.1, §1.4, §7.1, §11 step 4: a company
   controlled by its people's accounts, recovery by another account). Not in 0.5 (§C below). A
   company's controllers are its people's keys, often the same passkeys and security keys as
   their personal accounts (§3.3 allows that).
2. **An agent may be a controller if a keyring says so** (contract §8, from the Galley draft
   §3.2). 0.5 keeps 0.4's rule: never. Mike's principle is binding here.
3. **A verifier stricter than Colophon on ceremony origins** (contract §0.1 "Ceremony origins
   a verifier accepts"). Allowed for calls and sign-in only; for authority entries it would let
   two releases disagree about an account's history (§4.3, §8.5).
4. **`session.end`** is `endSessions` (§9.6), an authority entry, not a guarded transition.
5. **`head.maxAge` as an agreement term** is `policy.headMaxAge` in the keyring, default 300
   as the contract chose; the range is 30–86,400 (the contract's 30–3,600 is a valid Galley
   restriction).
6. **`importedFrom`** is replaced by a verified `predecessor` (§15.1).

## C. Deliberately left for later

Each is an extension a 0.5 reader meets as authenticated unknown content (`newerFormat`), so
adding it later changes no 0.5 format.

| Item | Source | Why not in 0.5 |
| --- | --- | --- |
| **Accounts as controllers**, cross-account signatures, admission receipts | Galley draft §3.1, §5.4, Q47; constitution 3.2 | A signature by "account C" is only as current as the verifier's knowledge of C's latest head; the attack review's P0-02 (a revoked company delegate amends another account) is closed only by an admission witness whose trust claim (Q47) is undecided. Mike's statements are met without it: one key may control many accounts, and a company is its own keyring held by people. The cost is that a person who loses a key updates each account they control; each update is one control-rule entry by their remaining keys. |
| **Guarded state** (authorities, transitions, claims, spending limits) | Galley draft §8, attack review P0-03/04/06, W0 closure "two contradictions" | The retry semantics (W0 closure §"Two contradictions") are not settled, and Galley's kernel is today's authority for these. Freezing a guarded log now would be an interim format. |
| **Modules as WASM**, releases, attestations, adoption, layers and `term` entries | Galley draft §11–§12, Q49, colophon#2 | No deterministic metering profile exists (Q49); colophon#2's report says its meter is inadequate for adversarial modules. The four built-in domain reducers stay (0.3 §6). |
| **Session-authored records**, provisional records and home receipts, epoch-key hand-off to sessions | Galley draft §4, §7; attack review P0-05; Q50 | Sessions act through calls to services, which write records under their own member keys with a `basis` (§12.4). This removes the provisional/final split and keeps a person's and an agent-member's records offline-final. An agent that needs to write offline gets its own member grant. |
| **`requires` (evidence about the acting key)**, signed custody and presence | Galley draft §6.1; 0.4 §11; W1 finding on `uv` | A raw key cannot show UV and no attestation format is chosen; the W1 slice had to trust a host bit. A term that can't be checked is worse than none. |
| **Signed history checkpoints** | Galley draft §15.4; contract R4 | See R4 above. |
| **Independent witnesses or gossip** | Galley draft §9.3, Q47 | `headQuorum` gives k-of-n homes; independence of homes is the owner's choice of homes. |
| **Pre-rotation** | Galley draft §15.7; constitution V.4 | The recovery role covers a stolen key; committing to next keys in advance doesn't fit passkeys, which can't be generated ahead of their ceremony. Not compared under a formal threat model. |
| **Proposing without reading** | Q46; Galley draft §15.1 | Needs an inbox key per namespace and its own sealing rules. `propose` includes `read` (§10.2). |
| **A strict online write budget** | 0.3 §5 ("needs a fresh sequencer") | Needs guarded state. `writes` stays 0.3's retrospective count. |
| **Several authorities for one log, ZK proofs, MLS, attested compute, workflows** | Galley draft §13 | Out of scope, as the draft said. |

## D. Every deferred or open item found in the repositories

Searched: the Colophon repository (all `spec/`, `docs/`, code comments and tests for
"deferred", "0.5", "later", "future", "not in 0.4", "TODO", "open question"); Galley `main`
(`docs/spec/colophon-0.5-draft.md`, `docs/spec/colophon-0.5-w0-closure.md`,
`docs/review/2026-11-10-colophon-0.5-attack.md`, `…-draft-2.md`, the constitution, QUESTIONS
Q46–Q51, DECISIONS D14–D85, P97–P100); the contract; Marginalia `docs/colophon/` and
`ColophonAuthority`.

| Item | Where | 0.5 |
| --- | --- | --- |
| "Recovery rotation, stewards and delegated sub-grants are deferred" | 0.3 §4 | Recovery and rotation settled by 0.4; stewards are thresholds; delegated sub-grants are links (§12). |
| One immutable grant per identity; replacing or extending needs a fresh key | 0.3 §4 | Extending: `renew` (§9.4). Changing scope still needs a new key, deliberately. |
| A grant can't give read in one namespace and write in another | 0.3 §6 | Settled: per-entry access (§10.1). |
| A strictly online budget needs a fresh sequencer | 0.3 §5 | Left (§C). |
| Custody and presence as signed fields | 0.4 §11 | Left (§C, `requires`). |
| Performance deviation D-F2-1 (200-entry replay 55 ms vs 20 ms) | `colophon-0.4.md`, `docs/performance.md` | Not a format item. Incremental verification from persisted state (§17.2) is how services avoid cold replays; the budget is not re-measured here. |
| PRF slot from a registration output (host-side check) | 0.4 §10 | Unchanged rule (§7.2); remains a host test. |
| Authority keep sets grow intrinsically | `docs/handoff-engine.md` "Remaining limits" 2 | Settled for `/5` records by author chains (§9.5). |
| No global freshness or anti-rollback | `docs/handoff-engine.md` 3; 0.3 §7.1 | Partly settled: heads, high-water marks and quorum (§13). Local cache rollback by an attacker who controls local storage remains out of scope. |
| Host relocation, recovery and leave protocols | `docs/handoff-blobs.md` "Gaps" | Homes and succession (§13, §15) cover relocation and leaving; app-level flows are host work. |
| Android packaging, blob GC, extension blob writes, background downloads, iCloud placeholders | `docs/followups.md`, `docs/handoff-blobs.md` | Host and SDK work, not formats. Unchanged. |
| Domain open questions | `docs/domains/*.md` | Domain modules, not formats. Unchanged. |
| W1 findings, all 22 rows | `spec/colophon-0.5-findings.md` | Each settled; see §E. |
| Galley draft §15 items 1–9 | Galley draft | 1 (propose includes read): settled yes. 2 (300 s window): `policy.callWindow`. 3 (large `kept`): author chains. 4 (self-contained proofs): removed with account controllers. 5 (metering), 6 (floats): left with modules. 7 (pre-rotation): left. 8 (admission witness): left with account controllers. 9 (custody): left with session hand-off. |
| Q46–Q50 | Galley QUESTIONS | Q46 settled (propose includes read). Q47, Q49, Q50 left with their features (§C). Q48 settled by author chains. |
| W0 closure "two contradictions" (retries vs revalidation; identity of a retry) | Galley | For calls: an identical body returns the recorded result and does nothing new; any byte difference under the same `requestId` is `refused:conflict` (§12.3 step 3). The guarded-log half is left with guarded state. |
| Attack review P0-01 … P2-17 | Galley | P0-01 (revocation backfill): exact digests plus author chains. P0-02, P1-14: removed with account controllers. P0-03, P0-04, P0-06: left with guarded state. P0-05: sessions don't author records. P1-07: `serves` isn't delegable through links at all. P1-08: purposes are exact; conditions evaluated by whoever decrypts. P1-09: `writes` is retrospective, as 0.3. P1-10: pipeline (§1, §12.3). P1-11: high-water and quorum. P1-12, P1-13: left with modules. P1-15: hint fetch rules (§5.2). P2-16: complete `/5` shapes in §8–§13. P2-17: §11.6. |
| Constitution "agents may hold authority" (D24) and "a signer is a key or another account" | Galley constitution 3.2, 4.1 | Agents hold authority through grants, never as controllers. Accounts as signers left (§C). The constitution text should be updated to match. |
| Marginalia "Two Keys" lowering rule: lowering `recoverThreshold` also needs a recovery quorum | `ColophonAuthority/AuthorityState.swift` `verifyKeyringChange` | Not adopted: 0.4 and 0.5 let the control quorum change any threshold. Recorded as a difference a Swift-to-0.5 succession can't carry over automatically; hosts should warn when a control-only quorum lowers recovery. |

## E. The W1 findings, settled

| Finding (spec-0.5-findings.md) | 0.5 |
| --- | --- |
| How links embed in a proof | Padded base64 of the canonical envelope, as 0.4 embeds requests (§2.2). Proofs as separate objects are gone: links travel in the call. |
| Canonical base64 | 0.5 readers refuse non-canonical spellings (§2.2). |
| Unknown terms vs signature order | Pipeline (§1): everything authenticated first, including the call signature, before `newerFormat`. |
| "Fetch from homes" | Fetching is the host's; the core returns `unavailable` (§12.3 step 4). |
| Two expiries | Members: `terms.expires`. Links: the link's own `expires`; link terms have no expiry. |
| Error codes for wrong account, malformed point, > 8 links, time | Signature or binding failures `badSignature`; structure `malformed`; time `refused:expired`. |
| Link outliving its parent; depth | `refused:expired` for lifetime (step 6), `refused:notNarrower` for depth. |
| Session on first link only; unguarded | First link only. There is no `unguarded` success: a call with no fresh head is `unavailable`. |
| `asOf` vs latest | Member and controller state from the latest held history; `asOf` must be present and match (fork otherwise). |
| Codes for audience, digest, replay, window | Separate: `refused:audience`, `refused:conflict`, `refused:window`. |
| What `body` digests | Calls carry `args` in plaintext (≤ 16 KiB); large inputs by digest inside `args`. |
| Nonce cache | `requestId` record per account and audience for 2 × `callWindow` (§12.4). |
| Name bounds | Kinds and purposes 1–128 bytes of a fixed alphabet; audiences 1–512; paths 1–8 segments of 1–64. |
| Duplicates and empty arrays | Distinct required everywhere; empty arrays never (fields are omitted instead). |
| `requires` and `uv` | Removed (§C). |
| Omitted `expires`, `writes` | Member terms: absent is unbounded. Links don't carry them. |
| Condition inclusion | Exact canonical equality per inherited predicate (§10.3). |
| `guard:` and `colophon.sign`/`publish` purposes | Gone with guarded state and modules. `colophon.` purposes are reserved for history and home access. |
| `args.` paths, missing paths, empty `all`/`any` | As W1 read them (§10.4). |
| Numbers | Exact integer comparison, no lossy casts (§10.4). |
| Predicate counting and depth | As W1 read them (§10.4). |
| Draft-flagged open items | §C and §D above. |

## F. Design forks decided, and the alternatives rejected

| Fork | Chosen | Rejected, and why |
| --- | --- | --- |
| 0.4 → 0.5 | In place, one `upgrade` entry, ID extended | Clean copy into a new account: loses every grant and member, needs new IDs everywhere and a new PRF assertion per passkey. Nothing about 0.4's authority needs replacing, only extending. |
| Swift keyring → 0.5 | Clean copy with a verified `handover`, same keys | Teaching every 0.5 verifier the Swift 0.1 record format and its root/keyring rules forever. The succession needs that verifier only at the copy and for anyone following the old ID. |
| Who adds a passkey | `addThreshold`, default 1, with role caps | Lowering `threshold` to 1 for everyone (weakens every change), or keeping 0.4 (two approvals for every new platform under Two Keys). |
| How sessions end | `endSessions` authority entry | A guarded log (needs an authority server for every person) or link expiry only (no instant end). |
| Who writes records | Members only | Sessions writing provisional records awaiting home receipts (the Galley draft): an agent's work would be pending until a home acts, and the receipt protocol is a new trust root. |
| Revocation keep set | Author chain heads plus exact digests | A clock cutoff (shown unsafe, P0-01); exact digests only (unbounded); a signed checkpoint (needs an orderer). |
| Environment restriction | Audiences | An `environments` term with deployment names inside the account's signed data. |
| Vault for backups | HPKE open with a non-Colophon `info` | Raw ECDH (opens every epoch) or seed export. |
| Epoch and slot labels | Unchanged (`/3`, `/4`) | `/5` labels: no security gain, and upgraded accounts would need both forever. |
| Head freshness default | 300 s | 3,600 s: a removed key would stay usable at services for up to an hour. A person whose only home is a phone can raise it. |
