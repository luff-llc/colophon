# Colophon 0.5 candidate vectors

**Status: hand-built for review, not replayed by any 0.5 implementation.** These files go with
[spec/colophon-0.5.md](../../../spec/colophon-0.5.md), revision 10. No 0.5 verifier exists yet,
so every `expected` outcome for 0.5 is the spec author's reading of the text. The bytes are
real: `/5` bodies are canonical JSON, and every signature verifies under ordinary ES256 (raw, or
WebAuthn over `authenticatorData ‖ SHA-256(clientData)` with the challenge checked), except
where a case says a signature is invalid on purpose. Spec §21 says which vectors must exist
before freeze. This directory holds those that could be built without an engine.

All keys are public test secrets (`keys.json`, `succession/keys.json`, `../../0.4/keys/keys.json`).
Never use them for real data.

## Regenerate and check

```sh
python3 -I conformance/0.5/candidate/generate.py          # write
python3 -I conformance/0.5/candidate/generate.py --check  # compare with the files here
```

`generate.py` runs `rules.py` (shared helpers and the cases that still hold), which runs `rules_v8.py` (pending transitions, who-wins rows, succession). It needs Python 3 and `cryptography`
(Apache-2.0 OR BSD-3-Clause; checked with 50.0.2), for tooling only. Signatures are
deterministic (RFC 6979), so regeneration is byte-identical. The generator also re-encodes all
267 published 0.4 authority bodies without duplicate names, and checks that its canonical encoder
reproduces them byte for byte.

## Contents

| Path | Spec | What |
| --- | --- | --- |
| `identifiers.json`, `upgrade/*` | §5.1, §16.1 | Identifiers; the 0.4 in-place upgrade |
| `account/`, `calls/*`, `heads/*` | §9, §12, §13 | Identity account (its home appointed by a transition and its determined `activate`), calls and heads. `calls/one-link` carries the member's condition (`ok`); `copied-link` then reaches the acting-key check |
| `rules/t-*` | §8.3, §8.6, §8.7 | Due time and deadline; held; the 7-day bound; identical and differing bytes; once only; evaluation before `activate`; vetoes (target, too few, sharing a unit, approve-only, after the deadline, 22 signers); ordering (a primary-covered entry before due keeps its seq; a backdated uncovered one doesn't; a `final` is never displaced); **finality as a recorded fact** (`final` with every witness, missing a witness, a non-witness head, out of order; a provisional addition signs nothing, a final one does; a full set finalizes earlier activations; finality survives a home rotation; a revoked witness and the veto that still stands); escalation; full sets with receipts and due from the receipt; consent and composites; `keep`; a recovery-rule home appointment refused below `threshold`; vault: removal of a slotted key without a vault change (retiring), by one recovery key, rotation by a `vault` entry, a `vault` entry when not retiring or without its own slot, a self-slot, `rekey` by a recover key; suspension |
| `rules/i-*` | §8.4, §13.1 | Immediate entries; the rate limit (verifier), planted keys, revocations outside the account limit, and the dormant-account burst a home refuses |
| `rules/call-*` | §12.3, §13.4 | Pending addition, provisional addition, after `final`, pending removal, suspended, suspended history read, a suspension expired by the clock, recover-only history read. Each carries `verifier.statuses` |
| `rules/veto-webauthn-*` | §4.3, §8.7 | A veto signature with and without UV, and from a call origin |
| `rules/row-*` | changes §H | Event sequences: rows 2, 3, 4, 8, 9, 10, 11, 12 (and a gone home revoked by one recovery key), 13 (the honest home serves the transition; the owner's veto stands), 17 |
| `rules/t-conflict-no-evidence`, `t-quorum2-veto-beats-removal`, `row-13-quorum1-hidden-transition`, `t-removal-unblocks-addition`, `t-revoke-home-*`, `t-planted-key-dropped`, `t-vault-by-approve-only`, `t-recovery-*` | §8.3, §8.4, §8.6, §8.7 | Revision 8: one per High of the second review of revision 7 |
| `encoding/number-ties.json` | §2.1 | Doubles with two equally near shortest decimals: the even last digit is canonical |
| `calls/link-unknown-operator-*` | §10.4, §12.3 | `any:[true, unknown]` is `ok`; `any:[false, unknown]` is `newerFormat` |
| `rules/origin-*`, `rules/replay-*`, `rules/removal-after-heads`, `rules/equivocation`, `rules/rollback`, `rules/malleated-envelope`, `rules/non-canonical-*`, `rules/invalid-expires-date` | §2, §4.3, §12, §13 | Unchanged from revision 3, rebuilt on the new account |
| `pairing/pairing.json` | §7.3 | Commitment and code |
| `succession/swift-*` | §13.5, §15.1, §16.3 | Receipt 60 s into the succession window (verified), 400 s (late, unverified); F before the due time; veto recorded as `successionVetoed`; a key removed before the last removal and before the delay can't veto, the last-removed key can, and so can a key removed within the delay before the genesis; a hand-over with an extra key needs two vetoers; root library signed by the root alone, and vetoed by the kit; WebAuthn and recover-set swaps; a premature thief freeze followed by the owner's verified layout-4 freeze; an entry after a verified F |
| `probes/swift-der/` | §16.3 | CryptoKit probe |

## What was run

- `generate.py --check`: 1,029 generated files match. The directory holds 1,035 files: those plus
  six sources (`README.md`, `generate.py`, `rules.py`, `rules_v8.py`, and the probe's
  `Package.swift` and `main.swift`).
- The fifth reviewer's signature checker (`sigcheck5.py`): 2,203 signatures, including heads in
  `final` entries and objects embedded in recording entries and `suspend`; 7 failures, all
  intended (two invalid call signatures, two origin cases, two veto cases, one `signers` mismatch).
- **0.4 engine** on `upgrade/*`: `newerFormat` everywhere except `foreign-signer` (`badSignature`).
- **Swift verifier** (Marginalia `c8280332`, unmodified): every full predecessor stops at its first
  freeze with `unsupportedStorageLayout(3)`.
- **CryptoKit DER probe** (macOS 27.0.1, 200 random keys): minimal DER and high-S accepted, every
  other form tested refused, including `r` or `s` of zero. iOS and visionOS were not probed.
- New-vault slots and `previousVault` seals are structurally valid synthetic bytes, not openable.
- No valid transition approaches the 622,592-byte envelope bound, so the quorum-8 size
  composition (§2.4) is checked by arithmetic, not by a vector.

## Required for freeze

Normative for spec §21 condition 1.

- **Keys, encoding and upgrade:**
  - every 0.4 key case as `/5`;
  - authority origins for entries, transitions and vetoes;
  - controller calls from call and authority origins;
  - non-canonical JSON and base64; malleated envelopes; invalid dates;
  - the 0.4 upgrade with every refusal.
- **Immediate entries:**
  - each §8.4 row accepted, and the same change refused as immediate;
  - tightening another key's authentication refused;
  - `layout` and `migration` as immediate refused;
  - two epochs for one namespace in a `rekey` refused;
  - the rate limit at every verifier, keys planted by an addition charged to their adder, revocations
    outside the account limit; at most four controllers per addition; headroom at 56 controllers
    and 224 slots.
- **Transitions:**
  - composite removal with a vault change and `previousVault`, slot rebasing at activation, and
    the `rekey` that follows; composite rules mixing components;
  - `keep`, including keys added after the anchor;
  - evaluation before `activate`: an anchor before the first home, an anchor at a lower past
    delay, a receipt by a revoked home (`malformed`), an anchor off the branch;
  - due time as `issued` + 300 s + delay; the veto deadline; receipt choice;
  - `signers` not matching the envelope;
  - determined recording entries from two homes, and two that differ only in receipts;
  - once only: a duplicate `vetoed`, a re-appended `activate`; the 7-day bound;
  - an `activate` that doesn't displace covered entries;
  - veto validity: count, disjoint units, eligibility, UV, origin, quorum, the deadline;
  - escalation at receipt and before activation, its reset, distinct transitions;
  - the full set (a) and (b), with removed keys counted and no receipts;
  - suspension: carried objects, its end, a void transition, one per unit, history reads,
    calls and immediate entries;
  - delta void cases;
  - mutual removal and the tie;
  - finality: the home set before, full sets, a `vetoed` after finality as evidence; rollback of a
    provisional activation and what it removes;
  - every row of changes §H.
- **Conflicts:** evidence; a fork with and without homes; `resolve`; a transition anchored on a
  losing branch.
- **Members and records:**
  - request coverage; pairing; `serves` and import;
  - renew; revoke with `kept` and up to 16 `heads`; `endSessions`;
  - `/5` headers; proposals.
- **Calls:** every §12.3 refusal; replay states (replay, conflict, abandoned); quorum; S.
- **Heads:** valid, stale, non-home, fork, rollback, equivocation.
- **Succession:**
  - `/5` and Swift (root and keyring, WebAuthn, `rotateRecovery`);
  - the genesis receipt window from the appointing entry;
  - the veto window: in time, too few, by a key no longer current, by a key current within the
    delay before the genesis, recorded as `successionVetoed`;
  - a premature freeze followed by a verified attempt;
  - an entry after the final one; two attempts.
- **Seed transfer:** the HPKE label, wrong nonces.
- **Finality:** `final` entries, revoked witnesses, a full set finalizing earlier activations, rule-1 conflicts with and without a primary head.
- **Vault:** retiring, rotation, self-slots, `rekey` by a recover key.
- **Exchange:** the pending listing (§14) and its cursors, against a simulated home.

## Still missing: these need an engine (implementation plan, step V1)

- Every 0.4 key case as `/5`; slots and rotation with real HPKE; slot rebasing with a slot added
  after the anchor; a vault change in an account with namespaces and its `rekey`.
- Namespaces: rekey (including two epochs for one namespace), shares, `/5` headers, author chains,
  revocation walks, proposals.
- `headQuorum` 2 with three homes, receipt forwarding, finality in order and rollback of a suffix,
  mutual removal, external-object limits, the replay states, the rate limit's byte budgets.
- `/5` succession, the migration entry with real digests, seed transfer.
- The Swift corpus on iOS and visionOS, and the dry run on a real library.
