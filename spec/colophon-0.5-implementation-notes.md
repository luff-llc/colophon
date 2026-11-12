# Colophon 0.5: implementation notes

**Status:** running list kept while building `colophon_core::v05` (plan Steps 0, 1 and 4, and
the call pipeline of Step 5) against [colophon-0.5.md](colophon-0.5.md) revision 5 (`a1decc6`).
Each item names the section, the readings, and the one chosen. None of these choices is
normative; each is a question for the next spec revision.

## Scope decisions

1. **"Step 0" is not a heading of the plan.** [changes §D](colophon-0.5-changes.md) calls the
   draft-1 move "implementation step 0"; the plan has it as the last bullet of Step V1. Done as
   written there (vectors to `conformance/0.5/legacy-draft-1/`, the test reads them there, a
   README says they aren't 0.5), and the module that replays them moved with them
   (`colophon_core::v5` → `colophon_core::legacy_draft1`), byte-identical vectors.
2. **Plan Step 1 names 0.4 files** (`keys/strict_json.rs`, `keys/descriptor.rs`,
   `keys/webauthn.rs`, `keys/envelope.rs`, `crypto.rs`). Changing them would change 0.4. The
   0.5 code is a new module beside 0.4 (`v05::*`); only `keys::strict_json::parse` is reused,
   unchanged.
3. **Out of scope, not implemented:** authority replay (§8.5), the §8.4 rule table, pending
   transitions (§8.7), conflicts and forks (§8.6), upgrade (§16.1), succession (§15, §16),
   slots and vault (§7), pairing (§7.3), the high-water mark, equivocation evidence, the
   revocation walk (its outcome is an input to admission), proposals (§11.6), epochs.

## Ambiguities and contradictions

| # | Section | Reading A | Reading B | Chosen |
| --- | --- | --- | --- | --- |
| 1 | §12.3 step 3, §12.4 (rev 5) | Step 3 "consults" the store, so a replay is refused at step 3 | The reservation is "after step 7 and before any effect", so nothing is looked at before | Both: a read-only look-up at step 3 (refuses replay/conflict early, writes nothing), and the compare-and-swap after **step 8**. "After step 7" also allows after 8; reserving after 8 means a `newerFormat` call reserves nothing, matching rev 5's "refusals no longer reserve". |
| 2 | §1, §8.5 vs §12.3 | Unknown content (`newerFormat`, §8.5 step 4) is decided **before** schema violations (`malformed`, step 5) | §12.3 decides well-formedness at step 1 and unknown content at step 8 | Parsers return `malformed` eagerly and collect unknown content separately (`Unknown`). Right for calls. An authority replayer (step 3) needs an unknown-content pre-scan before the typed schema, or an entry with both gets `malformed` where §8.5 says `newerFormat`. |
| 3 | §1, §3.1 | An unknown key `form` is unknown content, so `newerFormat` after authentication | The key can't verify anything, so no authentication is possible and the result is `badSignature` | `newerFormat` immediately: the object is of a known protocol and the reader can't proceed. |
| 4 | §10.4, §12.3 steps 7–8 | An unknown predicate operator makes step 7 undecidable | — | It evaluates as true and is recorded as unknown, so a call can never be `ok` with it: it ends `newerFormat` at step 8, or `outOfScope` if a known predicate fails first. |
| 5 | §10.4 | "1–8 dotted member names" counts the leading `args.` segment | Counts after dropping it | Counted as written (so `args.` plus 8 names is refused). |
| 6 | §3.1 `origins`, §10.1 audiences | "Printable ASCII" includes space (0x20) | Excludes it | 0x21–0x7E, as the 0.4 engine. |
| 7 | §2.2 dates | Year 0000 exists (ISO 8601 proleptic) | It doesn't | Refused; years 0001–9999. |
| 8 | §2.4 vs §19 | `clientData` over 8,192 bytes is `malformed` (bounds) | Inside an envelope any failure of an attached signature is `badSignature` | In a call envelope the bound is checked at parse (step 1, `malformed`). The WebAuthn primitive itself reports `ClientData`, which an authority caller maps to `badSignature`. |
| 9 | §12.1 | `notBefore` ≤ `expires` ≤ `notBefore` + `linkMaxAge` is a shape rule (`malformed`) | It is a validity rule (`refused:expired`) | `notBefore` ≤ `expires` is `malformed` at step 1 (no policy needed); exceeding `linkMaxAge` is `refused:expired` at step 6 (policy at S). |
| 10 | §3.3 rule 4 | A link `to.signing` equal to a principal's point is `malformed` | `badSignature` or a refusal | `malformed`: a repeat within the call at step 1; a principal's point at step 6 (needs the history). |
| 11 | §4.1, §12.3 | An assertion on a member call, or on a raw controller's call, is `malformed` | `badSignature` | Member + assertion: `malformed` at step 1 (knowable from the body). Controller form/assertion mismatch: `badSignature` at step 5 (needs the keyring). |
| 12 | §12.3 step 4 | A call naming an account the verifier doesn't hold | — | `unavailable` (no verified history). |
| 13 | §12.3 steps 4–5 | Freshness and `headQuorum` are read from the policy at S | S isn't known until freshness is | Freshness and quorum use the latest held policy; `callWindow` and `linkMaxAge` use the policy at S made field-wise stricter by every later held policy ("policy changes that shorten or restrict ... apply at once"). |
| 14 | §12.3 step 5 | A demotion or descriptor tightening after S applies; a loosening doesn't | — | The controller must pass under **both** its state at S and its latest held state: roles are intersected, `verification` from either, and the assertion is verified under both descriptors. |
| 15 | §12.3 step 5 | Member expiry compared with the call's `created` | With the verifier's clock | The verifier's clock, inclusive (`expires` is the last valid moment). |
| 16 | §13.3 | A head more than 60 s ahead is refused how? | — | `unavailable` (not acceptable yet), not `malformed`. |
| 17 | §9.4 | `renew` of a member with no expiry is valid (anything is "later") | Nothing is later than "never" | `malformed`: renew only extends, and there is nothing to extend. |
| 18 | §9.5 | `heads` is a list of digests | A list of `{namespace, digest}` ("sorted by namespace then digest") | `{namespace, digest}` objects, sorted, at most 16 per namespace. The shape is not written down anywhere. |
| 19 | §9.2, §9.4, §9.5 | `shares` and `epochs` have a 0.5 shape | — | Not restated in 0.5. Used the 0.3/0.4 epoch shape `{namespace, epoch, seals: {recipientID: {enc, ciphertext}}}` (§11.1). |
| 20 | §9.2 coverage | "equal or higher access" means the granted entry's | The requested entry's | The requested access is equal or higher than the granted (granted ⊆ requested). |
| 21 | §10.1 `serves` | Only `["home"]` is valid | Other values are unknown values | An unknown value is unknown content (`newerFormat`); duplicates are `malformed`. |
| 22 | §10.4 | `eq`/`in` values may be `null` | `null` only where a rule allows | Allowed: they are compared as canonical bytes. |
| 23 | §12.3 step 7, §13.4 | A recover-only controller's `colophon.history.read` call needs the purpose configured | A home has it implicitly | Configuration: a verifier lists it in its controller purposes. The vector `rules/call-recover-history-read` gives no `controllerPurposes` but `"role":"home"`; the runner treats a home as configuring it. The spec should say so. |
| 24 | §16.3, §4.3 | "Lenient" predecessor verification relaxes DER | Rev 4/5: §16.3 uses §4.3 step 5 unchanged | No lenient DER exists in the text. The `Strictness::SwiftPredecessor` parameter only changes the origin rule (general rule, no `origins`/`authorityOrigins`). Whether CryptoKit's `rawRepresentation` accepted r or s = 0 is unknown; refused. |
| 25 | §8.4 possession at genesis | The primary signer of a genesis also needs an `additions` item | Its primary signature is its possession proof | Not implemented (§8.4), but the `origin-*` vectors use reading B. |
| 26 | §12.3 step 6 | Per-link checks run link by link, the acting-key check last | Each check across all links | Link by link, in the sentence's order (signature/account/from, session, time, narrowing), then the acting key. |
| 27 | §6.1, rev 5 statuses | "Suspended" and "added by a non-final activation" | — | Inputs of the view (`ControllerStatus`), both `refused:revoked`; pending addition also `refused:revoked`; pending removal works. Members appointed by a non-final activation (homes) have no status in the view; §12.3 speaks only of controllers. |
| 28 | §2.4 rev 5 | The core enforces the portability floor | The floor is a service obligation | `v05::floor::FloorCounter`: counters the caller increments for entries, pending objects, bytes and signatures; limits never below the floor; `unavailable` beyond them; `past_half_floor` for the owner warning. |

## Vectors that look wrong

- **`calls/one-link`** expects `ok`. The member's terms carry
  `conditions: [{"prefix": ["args.task", "T-"]}]`; the link's terms carry none. §10.3: B narrows
  A only when "every predicate of A's `conditions` equals, by canonical JSON, some predicate of
  B's". So step 6 is `refused:notNarrower`. `generate.py`'s `narrow` omits the condition. The
  engine's own test builds the same call with the condition copied into the link: `ok`.
- **`calls/copied-link`** expects `badSignature`. It reuses the same link, which fails
  narrowing at step 6 before the acting-key comparison that ends step 6. With a narrowing link
  the engine returns `badSignature` (own test).
- **`account/` and every vector built on it (all of `calls/*`, `heads/*`, `rules/replay-*`,
  `rules/removal-after-heads`)** appoint the home by an ordinary `grant` entry at seq 3. Rev 5
  §8.4 lists `grant` as immediate only "not homes, not `import`", and home appointment as a
  pending transition. Under rev 5 that history is `malformed` at seq 3. The runner's fixture
  loader doesn't evaluate §8.4, so these vectors still run; a replayer would refuse them.
- **`calls/outside-window`**'s description cites step 3; 660 s is inside step 3's 3,600 s and
  is refused at step 4 by `callWindow`. Same outcome.
