# Colophon 0.5: guide

**Non-normative.** Rationale, host wording and history for [colophon-0.5.md](colophon-0.5.md).
Where this guide and the specification differ, the specification wins. Nothing here is a rule a
verifier applies.

## 1. One key's worst use of each immediate entry

The question for each row of §8.4's immediate table: can one key use it to disarm, outlast or lock
out the others?

| Kind | One key's worst use, and its bound |
| --- | --- |
| `grant`, `renew`, `revoke` | Admit or revoke members: bounded by the rate limit, charged to the key (§13.1), and by suspension; members a removed key admitted are listed for one-action revocation (§17.5). Revocations don't count toward the account limit, so a thief can't use the limit to stop the owner revoking. |
| `rekey`, `endSessions` | Churn epochs or sessions: the signer's rate limit; one epoch per namespace per entry. |
| `keyring` | Plant approve or sign keys: at most four per entry, each charged to the planting key's budget, and the 56/224 headroom; they never count, propose or veto. |
| `suspend` | Suspend one owner key: costs a veto, after which escalation stops repeats; one per unit at a time; it ends when the transition can no longer activate. |

## 2. Warning wording (§6.4)

- No home: "Without a home nothing waits and nothing can be vetoed: anyone with one of your keys
  can take the account at once."
- One home: "If your only home is down, nothing that has to wait can take effect. If it turns
  against you while someone has one of your keys, you can lose the account."
- Every control key on one device: "A thief with this phone holds every control key. Keep one on
  another device."
- One recovery key, or recovery keys kept together: "Someone who takes them can take your
  account. Keep two, apart."
- A company with two holders: at `threshold` 2, "neither of you can be removed without the other";
  at `threshold` 1, "either can act alone".

## 3. What `rp` means, explained (§3.2)

`rp` is the WebAuthn relying-party ID the credential belongs to. WebAuthn binds a passkey to it
forever, every assertion carries SHA-256 of it, and **every origin a browser lets use that
`rp` (the `rp` itself, every subdomain, and any related origin the `rp` publishes) can ask that
passkey for a signature over any challenge and for the PRF output for any salt.** Slot salts
are in the account's history, so any such origin can open that passkey's `prf` slots (§7.2).
Therefore:

- A host that registers a keyring passkey MUST use an `rp` whose every subdomain and related
  origin is operated as a ceremony origin of one release channel, and MUST NOT let a release of
  a different channel (for example staging) run code on any of them. A non-production release
  MUST use a different `rp` for any passkey it creates.
- Separating ceremony origins under one `rp` (for example an authority origin and a call origin)
  separates which origin can obtain **authority signatures** (via `authorityOrigins`). It does
  **not** separate **vault access**: every origin under the `rp` can read every `prf` slot of
  its passkeys. Code that must never be able to open the vault must not run on any origin under
  that `rp`; it needs its own `rp`, and therefore its own passkeys.
- Native builds are origins too. A beta or test build (TestFlight, an internal track) of an app
  is another release channel: it MUST NOT be listed in the production `rp`'s association files,
  or it MUST use another `rp`.
- **Security invariant:** whoever controls code on any origin a browser allows for an `rp` can
  read every `prf` slot of that `rp`'s passkeys. No field in an account changes this.
- The bare `rp` origin SHOULD serve only `/.well-known/` association files, because native-app
  assertions are commonly reported with that origin and it is then in `authorityOrigins`.

A verifier's own domain, origin or deployment never enters verification (§4.3).

## 4. Host interface (§17.1)

### Authority changes

1. **Unlock first** for any action that reads or seals epochs.
2. **New PRF slots need PRF before the body** (§7.2).
3. **Prepare:** the exact body, which signers satisfy which rules (§8.4), and each challenge.
4. **Finish:** the core verifies §4 and §8 before returning the record; nothing is written on
   failure.
5. **Prompts:** each body needs its own assertion; a hardware `raw` key with an authenticated
   context SHOULD sign every body of one action under one presence check.

### Calls, links, heads and verification

The core prepares links, calls, heads, receipts, transitions, vetoes and `suspend` entries as exact
bodies for the host to sign. It verifies calls (§12.3) and heads (§13.3) from inputs the host
supplies.

The **history verifier** needs no host identity. Per account it returns:
- the account ID, the legacy ID and the head;
- per entry, its signers and the rule met;
- per transition, its receipts, due time, vetoes, outcome and finality, plus v(u) for each unit;
- per controller ever present, its descriptor, roles, holder, first and last seq, and any
  suspension;
- per member, its keys, kind, label, custody, operator, terms, grant, renewals, session number and
  revoked seq;
- the homes and the primary, thresholds, `countBy` and policy;
- forks; the predecessor, successor and migration.

It resumes from persisted state. The core also exposes a standalone WebAuthn check returning `ok`
with the UV bit, or `badSignature` with the failed check, and a pure Swift predecessor verifier.
The host alone may open a non-`colophon/` HPKE seal to the vault for its own registered formats
(R10). The core never exports the seed or a raw ECDH output.

The history verifier also returns, per transition, its due time and veto deadline; per activation,
whether it is final and which homes it still needs; and per unit, v(u).

## 5. What to tell people, and what this protects (§17.5, §18)

- When an account is set up with one device: "If this device is stolen, nothing can veto what the
  thief does with it. Add a second key."
- In every notice: "Waiting protects who controls your account. It doesn't protect anything a
  stolen key could already read."

What the reference setup protects, plainly:
- **Eventual control of the keyring.**
- **Not** confidentiality of data a stolen key could already read: a recovery key with a slot,
  plus its PIN, reads the vault at once.
- **Not** uninterrupted service while a stolen online key acts during the delay. Suspension
  limits that.

Two homes at quorum 1 keep working with one down, but don't close the hostile-home case.

## 6. Not in this version (§20)

Each is a future authenticated extension:

- Accounts as controllers of other accounts; cross-account signatures.
- Guarded state: an authority ordering transitions, claims, spending limits.
- Modules as published WASM, releases, attestations, adoption, layered agreements.
- Records authored by session keys; epoch-key hand-off to sessions.
- `requires` and signed custody or presence evidence.
- Signed history checkpoints.
- Witnesses beyond `headQuorum`; pairwise account identifiers.
- Pre-rotation; proposals into namespaces the proposer can't read.

## 7. Review log

| Date | Reviewer | Findings | Resolution |
| --- | --- | --- | --- |
| 2026-11-11 | — | Revision 1 written | — |
| 2026-11-11 | Codex (Daybreak Blue) | 6 High, 5 Medium | Revision 2; changes §G.1 |
| 2026-11-11 | Independent attack review | 6 High, 8 Medium, 8 Low | Revision 2; changes §G.2 |
| 2026-11-11 | Galley contract R-A1–R-A11 | 11 requests | Changes §B |
| 2026-11-11 | Opus, second review of revision 2 | 8 High, 12 Medium, Low notes | Revision 3; changes §G.4 |
| 2026-11-11 | Codex, second review of revision 2 | 3 High, 7 Medium | Revision 3; changes §G.5 |
| 2026-11-12 | Codex, third review of revision 3 | 3 High, 6 Medium, lows | Revision 4; changes §G.7 |
| 2026-11-12 | Opus, third review of revision 3 (partial) | H1–H3, checks | Revision 4; changes §G.7 |
| 2026-11-12 | Opus and Codex, fourth reviews of revision 4 | H1–H10, M1–M11; 5 High, 5 Medium | Revision 5; changes §G.8 |
| 2026-11-12 | Opus and Codex, fifth reviews of revision 5; engine builder (28 questions) | H1–H5, M1–M8, lows; 4 High, 6 Medium; 28 ambiguities, 4 vectors | Revision 6; changes §G.9 |
