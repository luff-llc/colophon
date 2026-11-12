# Colophon 0.5 candidate vectors

**Status: hand-built for review, not replayed by any 0.5 implementation.** These files go with
[spec/colophon-0.5.md](../../../spec/colophon-0.5.md), revision 5. No 0.5 verifier exists yet,
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
| `identifiers.json`, `upgrade/*` | §5.1, §16.1 | Identifiers; the 0.4 in-place upgrade |
| `account/`, `calls/*`, `heads/*` | §9, §12, §13 | Identity account, calls and heads |
| `rules/t-*` | §8.6, §8.7 | Transitions with determined `activate`/`vetoed` bodies (unsigned): delay, held, expired by home clock, identical bytes from two homes; evaluation before `activate` (anchor before the first home, receipt by a revoked home); `signers` mismatch; vetoes (by target, too few, late); ordering (an entry issued before due keeps its seq; `vetoed` beats `activate`); escalation; full set (b), (b) missing a recover key, the phone's keys not being every control key; consent; void cases (no-op, add with different roles, breaking §6); migration without a predecessor; suspension (effect, immediate entry refused, without a transition, ended by a veto) |
| `rules/i-*` | §8.4, §13.1 | Immediate: removal refused, relabel, tightening policy, loosening refused, approve-only addition, the rate limit (65th entry) |
| `rules/call-*` | §12.3, §13.4 | Pending addition (refused), pending removal (ok), suspended (refused), recover-only history read (ok) |
| `rules/veto-webauthn-*` | §4.3, §8.7 | A veto signature with and without UV, and from a call origin |
| `rules/row-*` | changes §H | Event sequences: rows 2, 3, 4, 8, 9, 10, 11, 12, 13 |
| `rules/origin-*`, `rules/replay-*`, `rules/removal-after-heads`, `rules/equivocation`, `rules/rollback`, `rules/malleated-envelope`, `rules/non-canonical-*`, `rules/invalid-expires-date` | §2, §4.3, §12, §13 | Unchanged from revision 3 |
| `pairing/pairing.json` | §7.3 | Commitment and code |
| `succession/swift-*` | §13.5, §15.1, §16.3 | Receipt 60 s after the appointing entry (verified), 400 s (late, unverified); F before the window; veto recorded as `vetoed`; a key removed before the last removal can't veto, the last-removed key can; root library signed by the root alone, and vetoed by the kit; WebAuthn and recover-set swaps; a premature thief freeze followed by the owner's verified layout-4 freeze; an entry after a verified F |
| `probes/swift-der/` | §16.3 | CryptoKit probe |

## What was run

- `generate.py --check`: 568 files match.
- An independent signature checker verified all **560** signatures in `rules/` and `succession/`.
  It checks signature mathematics and challenges, but not UV or origin rules. The three
  `veto-webauthn-*` cases differ only in those rules.
- **0.4 engine** on `upgrade/*`: `newerFormat` everywhere except `foreign-signer`
  (`badSignature`).
- **Swift verifier** (Marginalia `c8280332`, unmodified): every predecessor through the entry
  before its first freeze is accepted, including the controller removals in the bounded-vetoer
  library. Every full predecessor stops at its first freeze with `unsupportedStorageLayout(3)`
  after verifying it.
- **CryptoKit DER probe** (macOS 27.0.1, 200 random keys): minimal DER and high-S accepted, every
  other form tested refused. iOS and visionOS were not probed.

## Still missing: these need an engine (implementation plan, step V1)

- Every 0.4 key case as `/5`; slots and rotation; a composite removal with a vault change and slot
  rebasing (needs HPKE).
- Namespaces: rekey (including two epochs for one namespace), shares, `/5` headers, author chains,
  revocation walks, proposals.
- `headQuorum` 2 with three homes, finality across homes and rollback on a late veto, mutual
  removal, external-object limits, the replay states.
- `/5` succession, the migration entry with real digests, seed transfer.
- The Swift corpus on iOS and visionOS, and the dry run on a real library.
