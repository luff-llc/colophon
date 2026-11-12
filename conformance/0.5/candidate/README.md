# Colophon 0.5 candidate vectors

**Status: hand-built for review, not replayed by any 0.5 implementation.** These files go with
[spec/colophon-0.5.md](../../../spec/colophon-0.5.md), revision 4. No 0.5 verifier exists yet,
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

`generate.py` runs `rules.py` (shared helpers and the cases that still hold), which runs `rules_v4.py` (pending transitions, who-wins rows, succession). It needs Python 3 and `cryptography`
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
| `rules/t-*` | §8.4, §8.7 | Pending transitions: activation after the delay, too early, expired; veto by the target, late veto, veto by too few keys, activation after a veto; escalation alone and with one more signer; full set and a one-key "full set"; recovery-set consent (demotion, raising `threshold`); a signer removed first; a delta that breaks §6; `vetoed` and `activate` beating other entries at one seq |
| `rules/i-*` | §6.2, §8.4 | Immediate entries: approve-only addition; a control addition or a loosening written as immediate (refused); tightening; headroom at 56 and 57 |
| `rules/call-by-pending-*` | §8.7, §12.3 | A key whose addition is pending can't call; a key whose removal is pending can |
| `rules/controller-call*` | §12.3 | WebAuthn controller calls from the call origin, the authority origin, a recover-only key |
| `rules/row-*` | §8.7 who-wins table | Event sequences with per-event outcomes: thief with a control key; with a recovery key; with one of each (owner with three keys); owner with both recovery keys and no device; burglar with both; an honest mistake; a hostile home countered by a second home |
| `rules/removed-key-equivocation`, `rules/malleated-envelope`, `rules/equivocation`, `rules/rollback` | §2.2, §8.6, §13.3 | Evidence, body-byte equality, heads |
| `rules/origin-*` | §4.3 | Authority origins with and without `authorityOrigins` |
| `rules/replay-*`, `rules/removal-after-heads` | §12.3, §12.4 | Replay identical and conflicting; a held removal |
| `rules/non-canonical-*`, `rules/invalid-expires-date` | §2.1, §2.2 | Encodings |
| `rules/keys-r4.json` | — | Public test keys used by revision-4 cases |
| `pairing/pairing.json` | §7.3 | Commitment and code |
| `succession/swift-*` | §15.1, §16.3 | Succession as a pending transition: the successor home's receipt of the genesis (`genesis-receipt.json`), F after the window (verified), F before it (unverified), a veto by an old key in the window, stale head, an entry after F (evidence; the succession stands), root library with root and recovery identity and with root only, `rotateRecovery` (current identities suffice), WebAuthn controllers, recover-set swap with and without consent, a recovery-added key vetoed, Two Keys lowered with and without recover signers |
| `probes/swift-der/` | §16.3 | The CryptoKit acceptance probe (Swift package, not part of the build) |

## What was run

- `generate.py --check`: 452 files match. The revision-3 cases built on attempt 2, cancels,
  provisional keys and digest tie-breaks are gone with those rules.
- An independent signature check (a separate script, not committed) verified all **594**
  signatures in `rules/` and `succession/` (primary, cosignatures, `additions`, `handover`,
  transitions, vetoes, receipts, `activate`/`vetoed` entries; WebAuthn with the challenge
  recomputed). None failed.
- **0.4 engine** (`Authority::replay` at `d8568c6`) on `upgrade/*`: `newerFormat` everywhere except
  `foreign-signer` (`badSignature: foreign controller`).
- **Swift verifier** (Marginalia `origin/main` `c8280332`, unmodified, in a scratch package):
  - every `succession/*/predecessor` up to the entry before F is accepted, including the WebAuthn
    libraries, the passkey's recovery-path addition, `rotateRecovery` and the Two Keys library;
  - every full predecessor stops at F with `unsupportedStorageLayout(3)` after verifying it.
- **CryptoKit DER probe** (`probes/swift-der`, macOS 27.0.1, 200 random keys):
  - accepted: minimal DER, high-S (DER and raw);
  - refused: an extra leading zero on `r` or `s`, an `r` or `s` with its top bit set and no 0x00
    pad (87 and 93 cases), long-form lengths, trailing bytes;
  - `JSONDecoder` accepts duplicate members and keeps the first.

  Revision 3 reported the unpadded form as accepted. That was a probe error (it built a minimal
  encoding when the top bit was clear) and is corrected. **iOS and visionOS were not probed.**

## Still missing: these need an engine (implementation plan, step V1)

- Every 0.4 key case as `/5`, with slots and rotation; a vault-changing transition with its
  `activate` shares.
- Everything with namespaces: rekey, shares, `/5` headers and AAD, author chains, revoke heads
  and the walk, renew shares, proposals.
- Seed transfer under the pairing scheme.
- Two homes with `headQuorum` 2 (latest receipt counts, one of two missing), late, early and
  non-home receipts of transitions; mutual removal by two pending transitions; the replay
  store's states.
- `/5` succession (a `successor` transition activated in the predecessor) and the migration
  entry.
- The Swift differential corpus on iOS and visionOS, and the dry run on a real library.
- Hint fetching (a host test).
