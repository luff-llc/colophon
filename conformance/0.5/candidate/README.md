# Colophon 0.5 candidate vectors

**Status: hand-built for review, not replayed by any 0.5 implementation.** These files go with
[spec/colophon-0.5.md](../../../spec/colophon-0.5.md). No 0.5 verifier exists yet, so every
`expected` outcome for `colophon-0.5` is the spec author's reading of the text. The bytes are
real: bodies are canonical JSON, and every honest signature verifies under ordinary ES256.

All keys are public test secrets (`keys.json` here, and `../../0.4/keys/keys.json`). Never use
them for real data.

## Regenerate and check

```sh
python3 -I conformance/0.5/candidate/generate.py          # write
python3 -I conformance/0.5/candidate/generate.py --check  # compare with the files here
```

Requires Python 3 and `cryptography` (Apache-2.0 OR BSD-3-Clause; checked with 50.0.2), for
tooling only. Signatures are deterministic (RFC 6979), so regeneration is byte-identical. The
generator also re-encodes all 267 published 0.4 authority bodies that have no duplicate member
names and checks its canonical encoder reproduces them byte for byte.

## Contents

| Path | What | Checked how |
| --- | --- | --- |
| `identifiers.json` | The 0.5 account ID (§5.1) of every published 0.4 genesis, its 32-character legacy prefix, and reference cases | SHA-256 only. The 0.4 library fixture's operation headers carry `library` equal to the legacy prefix (asserted by the generator). |
| `upgrade/*` | §16.1: an `upgrade` entry appended to published 0.4 chains, with refuse cases | **Replayed with the released 0.4 engine** (`Authority::replay`, see below). Expected 0.5 outcomes not replayed. |
| `account/` | A native 0.5 identity account with no namespaces: genesis, an agent grant (single rule), a home grant (control rule), and a head | Signatures verified by the generator. Not replayed by a 0.5 verifier. |
| `calls/*` | §12.3 cases against `account/`: member key, one link, copied link, invalid signature, wrong audience, outside the window, widening link, ended session, purpose and condition refusals, depth exceeded, expired link, unknown field after valid and invalid signatures | Call and link signatures verified by the generator (19). Outcomes not replayed. |
| `heads/*` | §13.3: valid, stale, signed by a non-home, fork | Signatures produced by the generator. Outcomes not replayed. |

### 0.4 engine replay of the upgrade cases

The released 0.4 core, at this branch's base (`d8568c6`), was run over each `upgrade/*/records`
with `colophon_core::authority::Authority::replay`. Results, 2026-11-11:

| Case | 0.4 engine | Expected 0.5 |
| --- | --- | --- |
| accept | `newerFormat: unknown authority kind` | ok |
| wrong-account, legacy-account, keyring-changed, policy-out-of-range, add-threshold-above, at-seq-two, then-v4-entry | `newerFormat: unknown authority kind` | malformed |
| then-v5-layout | `newerFormat: unknown authority kind` | ok |
| foreign-signer | `badSignature: foreign controller` | badSignature |

So a 0.4 app that meets an upgraded library stops with "update required" and does not touch
content, which is what §16.1 relies on. The published `seq-two-rekey` chain alone still
replays as `accept`.

## What is missing, and why

These need a 0.5 implementation's generator, or more hand-built cryptography than this
candidate attempted. They are listed in the implementation plan, step V.

- Every 0.4 key case re-expressed as `/5`, including the synthetic WebAuthn authenticator
  cases (§4.3, `authorityOrigins`, controller calls with assertions).
- Anything with namespaces: `/5` rekeys, grants with shares, revoke with `kept` and `heads`,
  renew with shares, `/5` operation headers, author chains, proposals and accept/decline,
  `kinds` and `conditions` on records. They need HPKE seals and AES-GCM payloads built to the
  spec; the generator here builds neither.
- Keyring transitions under the add and recovery rules, with slots.
- Succession with `handover` from `/4`, `/5` and `colophon/swift-keyring/2` predecessors.
- Seed transfer (§7.3), replay records (identical and conflicting `requestId`), head quorum
  above 1, equivocation and rollback across a persisted high-water mark.
- Hint fetching (host tests, not vectors).
