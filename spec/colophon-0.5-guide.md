# Colophon 0.5: guide

**Non-normative.** Rationale, host wording and history for [colophon-0.5.md](colophon-0.5.md).
Where this guide and the specification differ, the specification wins. Nothing here is a rule a
verifier applies.

## 0. What an account is (spec §0)

- **An account is a keyring.** A person, a company or a project is an account. Its identifier
  is the digest of its first authority record, so it means the same thing everywhere, before
  any server has heard of it, and it outlives every key, device, server and app.
- **Controllers hold authority.** A controller is a passkey, a security key, a device owner key
  or a recovery kit, with roles. How many are needed for each kind of change is a setting of
  the keyring, with a default and a range (§18).
- **Members do the work.** Apps, devices, agents and servers are members with **grants**: a
  signed, scoped, expiring permission from the account to a key. A key that has ever been a
  member of an account can never be its controller, and the reverse (§3.3).
- **One key may serve many accounts**, and anyone who sees two histories can tell that the same
  key controls both (§3.3). One person may hold many keys. The format knows no "work" or
  "personal" identity.
- **Data belongs to the owner.** Records are encrypted to the account's vault and to members
  that may read. Nothing in the format binds an account to a server, a deployment or a web
  origin, except the relying-party ID that WebAuthn attaches to each passkey (§3.2, §4.3).
- **Short sessions speak for members.** A member can pass part of its grant to a short-lived
  key through a signed **link**, and that key signs **calls** to services (§12). Sessions never
  appear in the account's history and never author records.
- **Homes keep and vouch for copies.** A home is a member appointed to keep the account's
  history and sign **heads**. One home is primary and orders new entries (§13).

**Words.** 0.4's *library* is an *account*; "library" remains the word apps may show. New
words: *terms*, *link*, *call*, *home*, *primary home*, *head*, *receipt*, *policy*,
*holder*, *upgrade*, *predecessor*, *successor*.

## 1. One key's worst use of each immediate entry

The question for each row of §8.4's immediate table: can one key use it to disarm, outlast or lock
out the others?

| Kind | One key's worst use, and its bound |
| --- | --- |
| `grant`, `renew`, `revoke` | Admit or revoke members: bounded by the rate limit, charged to the key (§13.1), and by suspension; members a removed key admitted are listed for one-action revocation (§17.5). Revocations don't count toward the account limit, so a thief can't use the limit to stop the owner revoking. |
| `rekey`, `endSessions` | Churn epochs or sessions: the signer's rate limit; one epoch per namespace per entry. |
| `vault` | Only while the vault is retiring, by a `control` or `recover` key current at the removal's anchor; keys the removed key planted are dropped. A thief who still holds such a key already reads the vault; his worst is a new vault without the owner's slots, which costs the owner a vault-change transition. |
| `keyring` | Plant approve or sign keys: at most four per entry, each charged to the planting key's budget, and the 56/224 headroom; they never count, propose or veto. |
| `suspend` | Suspend one owner key: costs a veto, after which escalation stops repeats; one per unit at a time; it ends when the transition can no longer activate. |

## 2. Warning wording (§6.4)

- No home: "Without a home nothing waits and nothing can be vetoed: anyone with one of your keys
  can take the account at once."
- One home: "If your only home is down, nothing that has to wait can take effect. If it turns
  against you while someone has one of your keys, you can lose the account."
- Every control key on one device: "A thief with this phone holds every control key. Keep one on
  another device."
- Recovery keys kept together: "Someone who takes them can take your account. Keep two, apart."
- Exactly one recovery key: "With one security key, someone who has any one of your devices can
  block your recovery for good. Add a second, or remove it."
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

**What freshness gives (§13.3).** With `headQuorum` 1, heads give availability and a bound on how
stale an honest primary's view can be; a compromised home key can keep signing fresh heads over an
old history for a verifier that has seen nothing newer, which then learns of removals only from
other sources (devices, other homes). The account bounds this by raising `headQuorum` with
independently run homes, and by appointing a new primary.

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

**What a host can tell the person (§18)** (for the reference person; adapt the numbers):

> Your account is held by your devices, your passkey and two security keys. If you lose one, or
> one is stolen, you can remove it, and no one can take your account without giving you three
> days in which any of your other keys can say no. That protection has limits. Someone who gets
> more of your keys than you still hold (for example your phone and one security key, or
> everything kept in one place) can take the account after three days even if you object; someone
> who gets both security keys can take it at once. So keep one security key away from home, and
> open the app at least every few days. A stolen key can still read whatever it could already
> read, and can keep signing in until you suspend or remove it. Your account's history is kept by
> two services: if one is down, removals still work and new keys wait; if one turns dishonest
> while someone also has one of your keys, you can lose the account.

**One recovery unit.** Have none or at least two recovery units. A unit is a key when the account
counts keys (the person reference does, so your two security keys are two units), and a holder
when it counts holders (the company reference): then two security keys that are both yours are
one unit. With one recovery unit, recovery is only a pending transition, and a thief holding any
one control unit can veto it once and then block it for good: one against one is a stall. Two
units, kept apart, recover at once and can't be vetoed.

What the reference setup protects, plainly:
- **Eventual control of the keyring.**
- **Not** confidentiality of data a stolen key could already read: a recovery key with a slot,
  plus its PIN, reads the vault at once.
- **Not** uninterrupted service while a stolen online key acts during the delay. Suspension
  limits that.

At `headQuorum` 1, one hostile home together with one stolen control or recovery key can still
win, because it can receipt a backdated transition and hide vetoes. Three homes at `headQuorum` 2
close that and keep working with one home down. Two homes at quorum 1 keep working with one down,
but don't close it.

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

## 7. Succession rationale (§15.1)

**Why the root alone signs a root library's hand-over:** in the shipping app the root alone can
`rotateRecovery()`, and the kit alone can `recover()` a new root, so requiring both adds friction
without stopping either thief. What protects the owner is the veto window.

## 8. Review log

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
| 2026-11-12 | Opus and Codex, sixth reviews of revision 6; engine attack (12 gaps) | H1–H6, M1–M11, lows; 3 High, 5 Medium; 12 gaps | Revision 7; changes §G.10 |
| 2026-11-12 | Codex, second review of revision 7 | 5 High, 4 Medium, 2 Low | Revision 8; changes §G.11 |
| 2026-11-12 | Codex, review of revision 8 | 1 High, 4 Medium, 1 Low | Revision 9; changes §G.12 |
| 2026-11-12 | Codex, review of revision 9 | 1 High | Revision 10; changes §G.13 |
| 2026-11-12 | Confirmation review of revision 10 | units, not controllers; sufficient not necessary; stale wording | Revision 11; changes §G.14 |
| 2026-11-14 | Claude, engine check of the 0.5 history verifier (PRs #5 and #6) | 3 High, 4 Medium, 6 Low | Revision 12 answers M1, M2, M4, L2, L5 and the chain bound; changes §A.8, §G.16 |
| 2026-11-14 | Claude, independent check of revision 12 (PR #7) | 3 High, 5 Medium, 4 Low | Revision 12 (fix round); changes §A.8, §G.17 |
| 2026-11-14 | Claude, checks of the write side: authority builders (E1), vault, slots and pairing (E2), homes and calls (E3), and the integrated write side | resolve, rollback, receipt and head choices, late veto, two heads, slot shape, equivocation evidence, seven text gaps | Revision 13; changes §A.9, §G.18 |
