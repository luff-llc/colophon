# Colophon 0.5: implementation notes

**Status:** running list kept while building `colophon_core::v05` (plan Steps 0, 1 and 4, and
the call pipeline of Step 5) against [colophon-0.5.md](colophon-0.5.md) revision 6 (`281e7c4`).
Revision 6 made most of the earlier list into text (dates 0001–9999, printable ASCII, §1's single
verification order, unknown `form`, renew without expiry, `revoke.heads`, the epoch shape,
coverage, `serves`, `null` in `eq`/`in`, condition paths, three-valued conditions, the call
policy rules, link-by-link checks, the replay look-up and reservation, home purposes). Those
items are gone from this list. What remains is open.

## Scope decisions

1. **"Step 0" is not a heading of the plan.** [changes §D](colophon-0.5-changes.md) calls the
   draft-1 move "implementation step 0"; the plan has it as the last bullet of Step V1. Done as
   written there, and the module that replays the vectors moved with them
   (`colophon_core::v5` → `colophon_core::legacy_draft1`). The vectors are byte-identical.
2. **Plan Step 1 names 0.4 files.** Changing them would change 0.4, so the 0.5 code is a new
   module beside 0.4 (`v05::*`). Only `keys::strict_json::parse` is reused, unchanged.
3. **Out of scope, not implemented:**
   - authority replay (§8.5), the §8.4 rule table, pending transitions (§8.7), forks (§8.6);
   - upgrade (§16.1), succession (§15, §16);
   - slots and vault (§7), pairing (§7.3), epochs;
   - the high-water mark, equivocation evidence, the revocation walk, proposals (§11.6).

   §8.7's outcomes enter as inputs: `ControllerStatus` (pending addition or removal,
   suspended, added-but-not-final) and `MemberStatus` (added-but-not-final, including homes),
   and `AuthorView::provisional` for records.
4. **The view is sealed.** `AccountView::from_history_verifier` is the only constructor. It
   checks every structural invariant and returns an error, never a panic. Its only production
   caller will be the Step-3 history verifier. Heads enter only as envelopes, and `verify_call`
   verifies each one with `verify_head` at the call's clock. Controllers, members, policies and
   terms are sealed types built by `parse` or by validating constructors. Unknown content is
   part of each value (`unknown()`), never an out-parameter.

## Still open

| # | Section | Question | What this implementation does |
| --- | --- | --- | --- |
| 1 | §12.4 retention | Retention of 7,200 s with `\|created − now\| ≤ 3,600 s`, compared with `<`, lets a call created at T + 3,600 be accepted at T and again at exactly T + 7,200 | Keeps reservations 7,260 s (2 × 3,600 s + 60 s skew), compared inclusively: retained while `now − reservedAt ≤ 7,260 s`. A compile-time assertion states the invariant, and a test checks the boundary values. **Proposed §12.4 sentence:** "A reservation is kept while `now − reservedAt ≤ 7,260 s` (more than twice the 3,600 s window of §12.3 step 3, plus 60 s of clock skew), so no call it guards can be accepted again." |
| 2 | §4.3 general rule | Any prefix without `/ : ? # @ \`, empty labels or edge dots is allowed (uppercase, `%`, spaces, non-ASCII) | Safe reading: the whole host must follow the `rp` label grammar. This refuses `https://A.id.example`, `https://%2e.id.example`, `https://a b.id.example` and `https://évil.id.example`. Divergence risk: a verifier on the literal rule would accept those origins. |
| 3 | §2.1 numbers | Two shortest decimals that both round-trip | Ryū's tie-breaking (ties to even, like ECMAScript); the ported attack test `number_forms_exhaustive` checks it against an independent model. The spec should say "ties to even". |
| 4 | §2.3 strings | Lone surrogates (`\ud800`) | Refused everywhere, including inside members a reader ignores and in `clientData`. JavaScript's `JSON.parse` accepts them, so a TypeScript port must refuse them explicitly. |
| 5 | §2.3 nesting | No nesting bound | serde_json's recursion limit: 127 levels parse, 128 or more don't. The spec should state a bound. |
| 6 | §1, §8.5 | The unknown-content scan for authority entries | `v05::prescan::authority_fields` reports unknown content without failing on malformed known fields, so a replayer can decide step 4 (`newerFormat`) before step 5 (`malformed`). It covers genesis keyrings, policies, controllers, descriptors, grant, renew, revoke and endSessions fields, terms and epoch objects. |
| 7 | §4.3, §8.4 | Which signatures are "with UV" | `AuthorityRule` fixes the rule: UV for control, recovery, `keyring`, transition, veto and `handover` signatures. Single-rule, `suspend` and possession signatures need UV only with `verification`. A `sign` controller's possession proof uses the general origin rule. `handover` needing UV is this implementation's reading (§16.3 marks UV for predecessor keys). |
| 8 | §12.3 step 7 | Members at a home: `colophon.history.read` and `colophon.home.read` are allowed to "any current member" (§13.4, §14) | Allowed for a member calling with its own key (no links) at the home's own endpoint. `colophon.home.write` and linked calls still need terms granting the purpose. The rule for links is not written. |
| 9 | §12.3 step 5 | A controller removed after S and re-added after S | Refused (`refused:revoked`): the removal after S applies, and an addition after S doesn't count. |
| 10 | §12.3 step 5 | A controller whose key form differs between S and the latest state (for example WebAuthn with `verification` at S, raw later) | The call must meet both forms; since a call can't, it's `badSignature`. |
| 11 | §1 unknown `form` | When is `newerFormat` reported for a call by a controller with an unknown key form? | After possession (step 2), authorization (roles, purpose) and extensions: it is the last result before `ok`, and it reserves nothing. Authority signatures return `Checked::UndecidableForm` for the caller to defer. |
| 12 | §16.3 | A lenient predecessor DER form | None exists in the text. `Strictness::SwiftPredecessor` changes only the origin rule (general rule, no `origins`). Whether CryptoKit's `rawRepresentation` accepts r or s = 0 is unknown; refused. |
| 13 | §8.4 possession at genesis | Does the primary signer also need an `additions` item? | Not implemented (§8.4); the `origin-*` vectors use "no". |
| 14 | §11.5 after opening | An unknown condition operator deciding a record's admission | `Admission::NewerFormat`. §11.5 has no `newerFormat` row. |
| 15 | §13.3 | A head more than 60 s ahead | `unavailable`, as revision 6 now says; it doesn't count for quorum. |

## What the vectors should carry

The runner derives §8.7 statuses from structured data, never from descriptions:
- a transition object that no `activate` in the records embeds is pending;
- a `suspend` entry suspends its key;
- an activation is final once every home current before it has a fresh head covering it.

The last one is a fixture-level reading of §8.7 "Finality". Vectors that depend on a status
should state it, so that no implementation has to compute §8.7 to read them, for example:

```json
"verifier": {"statuses": {"controllers": {"<id>": "pendingAddition|pendingRemoval|suspended|addedNotFinal"},
                          "members": {"<id>": "addedNotFinal"}}}
```

Needed by: `rules/call-by-pending-addition`, `call-by-pending-removal`,
`call-by-provisional-addition`, `call-by-suspended` and `call-suspended-history-read`. The home
appointments in `account/` and every `rules/` base history need `members` statuses too (final).

## Vectors that look wrong

None at revision 6. The four flagged at revision 5 (`calls/one-link`, `calls/copied-link`,
`account/`, `calls/outside-window`) are fixed in the revision-6 corpus, and every in-scope vector
passes.
