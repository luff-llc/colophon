# Colophon 0.5 candidate vectors

**Status: hand-built for review, not replayed by any 0.5 implementation.** These files go with
[spec/colophon-0.5.md](../../../spec/colophon-0.5.md), revision 2. No 0.5 verifier exists yet,
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

`generate.py` runs `rules.py` for the revision-2 cases. It needs Python 3 and `cryptography`
(Apache-2.0 OR BSD-3-Clause; checked with 50.0.2), for tooling only. Signatures are
deterministic (RFC 6979), so regeneration is byte-identical. The generator also re-encodes all
267 published 0.4 authority bodies without duplicate names, and checks that its canonical encoder
reproduces them byte for byte.

## Contents

| Path | Spec | What |
| --- | --- | --- |
| `identifiers.json` | §5.1 | 0.5 IDs of every published 0.4 genesis; legacy prefixes; reference cases |
| `upgrade/*` | §16.1 | `upgrade` on published 0.4 chains, and refusals |
| `account/`, `calls/*`, `heads/*` | §9, §12, §13 | Identity account with an agent and a home; 14 call cases; 4 head cases |
| `rules/rs-*` | §8.4 | Recovery-set rule: lower `recoverThreshold`, add a recover key, remove one; each with and without recover signers |
| `rules/add-*`, `rules/provisional-*` | §8.4, §17.3 | Add rule at threshold 1 (one approval) and 2 (provisional: approve only, `until`, no slot); possession missing and wrong |
| `rules/issued-backwards` | §8.1 | Monotonic `issued` |
| `rules/readd-removed-controller` | §8.3 | Remove a never-slotted controller without rotation, re-add it |
| `rules/member-key-as-controller`, `rules/former-controller-as-member` | §3.3 | Principals across time |
| `rules/sign-controller-authority` | §6.1 | A `sign` controller can't sign authority |
| `rules/holders-*` | §6.2 | `countBy` `holders` |
| `rules/recovery-*`, `rules/delayed-signer-*`, `rules/cancel-*`, `rules/delay-zero-with-home` | §8.4, §13.5 | Receipts, the recovery delay, the cancel rule, the delay floor |
| `rules/successor*`, `rules/entry-after-successor` | §15.2 | Terminal successor under the recovery-set rule |
| `rules/fork*`, `rules/resolve-without-recovery` | §8.6 | Forks on both branches, `resolve` |
| `rules/origin-*` | §4.3 | Authority origins with and without `authorityOrigins` (synthetic authenticator) |
| `rules/controller-call*` | §12.3 | Controller calls from the call origin, from the authority origin, and by a recover-only key |
| `rules/replay-*`, `rules/removal-after-heads` | §12.3, §12.4 | Replay identical and conflicting; a held removal beyond the heads applies at once |
| `rules/equivocation`, `rules/rollback` | §13.3 | Evidence object; rollback below the high-water mark |
| `rules/non-canonical-*`, `rules/invalid-expires-date` | §2.1, §2.2 | Unsorted keys; a non-zero padding bit; February 30 |
| `pairing/pairing.json` | §7.3 | Commitment and code for fixed inputs; two mismatching reveals |
| `succession/swift-*` | §15.1, §16.3 | Swift keyring and root libraries frozen by their final `layout` entry; stale head; an entry after the final one; two successors; Two Keys lowered with and without recover signers; root library with and without the recovery identity |

## What was run

- `generate.py --check`: 299 files match.
- An independent signature check (a separate script, not committed) verified all **246**
  signatures in `rules/` and `succession/` (primary, cosignatures, `additions`, `handover`;
  WebAuthn with the challenge recomputed). None failed.
- **0.4 engine** (`colophon_core::authority::Authority::replay` at `d8568c6`) on `upgrade/*`:
  `newerFormat: unknown authority kind` for every case except `foreign-signer`
  (`badSignature: foreign controller`).
- **Swift verifier** (Marginalia `origin/main` `c8280332`: `ColophonCore`, `ColophonStore` and
  `ColophonAuthority` built unmodified in a scratch package, then `AuthorityState(records:)`):
  - every `succession/*/predecessor` up to the entry before the final one is **accepted**: keyring
    adoption, the sealed slot's structure, the Two Keys thresholds and the root library;
  - every full predecessor stops at the final entry with **`unsupportedStorageLayout(3)`**, after
    verifying its signature;
  - the rival final entry also stops with `unsupportedStorageLayout(3)`;
  - a copy with one bit of the final signature flipped gives `badSignature("authority entry 3")`.
  So released Swift readers verify and then stop at the freezing entry, as §16.3 says.

## Still missing: these need an engine (implementation plan, step V1)

- Every 0.4 key case re-expressed as `/5`, including slots, rotation and the WebAuthn refusal
  cases.
- Everything with namespaces: these need HPKE seals and AES-GCM payloads built to the spec. That
  covers rekey, grant shares, `/5` headers and AAD, author chains, revoke with `kept` and up to 16
  `heads` (including a fork and a walk through a refused header), renew with shares, and proposal
  ordering.
- Keyring changes that rotate the vault (removing or demoting a slotted controller, cancelling a
  slotted recovery addition). The re-add and removal vectors here use never-slotted controllers
  for that reason.
- Seed transfer under the pairing scheme (an HPKE seal with the transfer label).
- A call evaluated with two homes and one stale head, and additions after S being ignored. These
  need a second home's head and a verifier model. The single-home cases are here.
- `/5` succession with fresh heads over the predecessor's `successor`, and the migration entry
  with a real copy's view digests.
- Hint fetching. That is a host test, not a vector.
