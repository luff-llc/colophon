# Colophon 0.5: implementation plan

**Status:** plan for [colophon-0.5.md](colophon-0.5.md), revision 13, 2026-11-14. Steps 0, 1 and 4
are merged into `spec-0.5` (luff-llc/colophon#4); revision 7's effect on them is listed under
each step. The §8.7 state machine (step 2's transition part and step 3's conflict rules) is the
state table of §8.7, over the persisted state of §17.2. No engine code has
been changed by the spec work. Steps are in order. The vectors come first, because §21 says the
spec can't freeze without them, and every verifier step is then tested against them.

Rules carried over from `docs/handoff-keys-04.md`:
- The core stays sans-IO with no RNG.
- No new Rust dependency: the existing `p256`, `aes-gcm`, `hkdf`, `sha2`, `serde`, `serde_json`
  and `base64` suffice.
- Swift 6 with no third-party dependencies.
- Duplicate JSON names are found by the existing strict pass, never resolved first-wins or
  last-wins.

## Step V1. Finish the vectors, before any verifier code

The 0.4 core already has every primitive the missing vectors need: HPKE (`hpke.rs`), slots and
vault (`slots.rs`, `vault.rs`), AES-GCM and software keys (`crypto.rs`) and the synthetic
authenticator (`keys/testing.rs`). A generator can build 0.5 bytes from those without a 0.5
verifier.

- **Files.** New `crates/colophon-core/tests/v5_candidate.rs`, which writes to
  `conformance/0.5/`, is opt-in, and is deterministic from published seeds. Port the cases in
  `conformance/0.5/candidate/` (then built by the Python `generate.py` and `rules.py`) into it, so one generator
  owns them all. The ported files must come out byte-identical, or the difference becomes a
  spec question. **Status: done.** The port is `v5_candidate.rs` with helpers in
  `tests/v5_candidate/`. Its check mode reproduces all 1,078 files byte for byte, and
  `generate.py`, `rules.py` and `rules_v8.py` are deleted. The missing vectors below are still to
  be added to this generator.
- **Missing vectors to produce** (each listed in §21 and in the candidate README):
  1. Every 0.4 key case as `/5`, including slots, rotation and every WebAuthn refusal.
  2. Namespaces:
     - rekey and grant shares;
     - `/5` headers with AAD;
     - author chains;
     - revoke with `kept` and up to 16 `heads`, a walk through a refused header, a missing
       intermediate, and a fork;
     - renew with shares;
     - proposals in each order, including a resolution whose clock is not higher.
  3. Rotating keyring changes: removing or demoting a slotted controller.
  4. Seed transfer under the pairing scheme.
  5. Calls with two homes and one stale head; additions after S ignored.
  6. `/5` succession with fresh predecessor heads; the migration entry with real view digests.
  7. Transition cases not yet built:
     - two homes with `headQuorum` 2; late, early and non-home transition receipts; receipt
       forwarding; a home that missed the window;
     - mutual removal by two transitions;
     - a vault-changing transition with real HPKE slots and `previousVault`, in an account with
       namespaces, and its `rekey`;
     - rollback of a provisional activation with a suffix; finality in order;
     - a `/5` `successor` transition.
     Revision-3 items not yet built:
     - a future `issued` held;
     - possession from a non-authority origin, and two `resolve`s;
     - a quorum-2 stale call, and a recovery at a non-primary home colliding with a primary entry;
     - the replay store's `pending` state;
     - the whole §21 list.
  8. **The Swift differential corpus**, extended from `probes/swift-der`:
     - every DER and raw form, run through both the released Swift verifier and the §16.3
       verifier, on macOS, iOS and visionOS;
     - duplicate and missing `clientData` members.

## Step 0. Move the draft-1 vectors

Move the draft-1 vectors (`conformance/0.5/speaks-for`, `conformance/0.5/terms`) to
`conformance/0.5/legacy-draft-1/`, with the module that replays them, update the test to read them
there, and say in a README that they aren't 0.5. (Done on `engine-0.5-foundation`.)

## Step 1. Encoding, keys and origins

A new 0.5 module beside 0.4 (`colophon_core::v05`), so that 0.4 behaviour can't change; it may
reuse 0.4 code unchanged (`keys::strict_json::parse`), and changes no 0.4 file.

- **Revision 7 changes here:** bounds transition 622,592, veto envelope 131,072, veto body 4,096,
  receipt envelope 1,024, receipt body 512; ties to even; lone surrogates refused; nesting at most
  64; the origin-prefix label grammar; an unknown form is the last result before `ok`.
- **Revision 6 changes here:** envelope bounds for transitions (655,360), vetoes (98,304) and
  receipts (2,048) in §2.4; an oversized `clientData` is `malformed` in every envelope; dates are
  years 0001–9999; printable ASCII is 0x21–0x7E; one verification order (§1), with an unknown
  key `form` `newerFormat`.

- Canonical re-encoding check for `/5` bodies; canonical base64 including padding bits; strict
  calendar dates with exactly three fraction digits; bounds before allocation (§2).
- Descriptor: web origins in `origins`; `authorityOrigins`.
- WebAuthn verifier: an `authority` flag that applies the authority-origin rule (§4.3); a call
  path that takes the verifier's configured call origins; flags and counter policy.
- Envelope: `additions`, `handover`; call envelopes with an optional `assertion`.
- Export the standalone WebAuthn check (contract R2).

## Step 2. Keyring, policy and rules

Files: `authority.rs`, `slots.rs`, `vault.rs`.

- `Keyring` gains `addThreshold`, `countBy` and `policy`; controllers gain `holder`, `audiences` and
  role `sign`; bounds of 64 controllers and 256 slots.
- Rule evaluation (§8.4): control, recovery, single and member rules; possession; recovery-set consent; the larger-threshold count.
- **Counting units** (§6.1) used by every count.
- **Pending transitions (§8.7).** This is the core state machine, and it should be built and
  reviewed on its own before anything that depends on it:
  - transition, veto and receipt objects;
  - due time `issued` + 300 s + delay once `headQuorum` receipts exist; the veto deadline; receipt
    choice by lowest home ID;
  - veto validity (signer count, disjoint units, eligibility, receipts before the deadline);
  - the escalation counters v(K) computed from `vetoed` entries;
  - the full-set check;
  - delta application at `activate`, with the void cases;
  - the 7-day bound;
  - composite changes and vault rotation with slot rebasing (§8.3);
  - evaluation against the state before `activate`;
  - determined, once-only recording entries (`activate`, `vetoed`, `successionVetoed`), all
    unsigned, with `malformed` for invalid receipts, non-determined fields and the 7-day bound;
  - `keep`; `previousVault` and the `rekey` that follows a vault change;
  - `final` entries (witness heads verified in the state before the activation; revoked witnesses
    excepted), in order; additions counting for nothing until final; rollback of the suffix;
  - the vault's retiring state, `vault` entries and self-slots;
  - suspension carrying its transition, with its computable end;
  - the rate limit (§13.1), charged signers included;
  - the persisted state of §17.2;
  - external-object limits.
- The §8.4 classification as data: every change kind is immediate or pending, and the default
  for unknown changes is pending.
- Headroom: a `keyring` entry may not leave more than 56 controllers or 224 slots, and adds at
  most four controllers; only `activate` uses the rest.
- Holder labelling with the key's co-signature.
- Rotation only for controllers some slot ever named (§8.3). Re-adding a removed controller.
- Seed transfer (§7.4) and pairing (§7.3): `begin_pairing`, `reveal`, `pairing_code`.
- The restricted vault HPKE open (§17.1).

## Step 3. Authority `/5`, forks, upgrade and succession

Files: `authority.rs`, `model.rs`, `protocol.rs`, `library.rs`; new `swift_predecessor.rs`.

- Chains: all `/5`, or `/4` through one `upgrade` then `/5`.
- Monotonic `issued`; future entries held.
- Kinds:
  - new: `renew`, `endSessions`, `resolve`, `migration`, `successor` (terminal);
  - changed: `revoke` (`member`, `kept`, `heads`), `grant` (`terms`), and genesis (optional
    `predecessor`, zero namespaces).
- Conflict classification (§8.6): `activate` and `vetoed` first, equivocation evidence, and forks resolved only by a `resolve` transition. Body-byte equality everywhere.
- `upgrade` (§16.1) and the conversion of 0.4 grants to terms.
- Succession (§15.1). For `/5` predecessors, use the core's own verifier.
- **Swift predecessor verifier in Rust** (§16.3), a pure function of stored bytes, so the WASM
  build and every binding carry it. Its vectors are `conformance/0.5/candidate/succession/*`,
  already replayed by the Swift source. A TypeScript port for Galley must pass the same files.
- Receipts (§13.5) as inputs to replay.

## Step 4. Members, terms and records

Files: `authority.rs`, `library.rs`, `model.rs`, `records.rs`, `imports.rs`, `domain.rs`,
`domains/*`, `engine.rs`, `storage.rs`, `checkpoint.rs`.

- Request `/5` with `custody` and `operator`; grant coverage; import and `serves` rules;
  `memberRule`; `renew` only extends.
- Operation header `/5` with the new AAD.
- Author chains: one writer per key, persisted heads, and a stop when there are several maximal
  heads.
- Admission (§11.5), including the walk with up to 16 heads; held `unavailable` on a missing
  intermediate; `wrongFormat` fences.
- Proposals (§11.6) with the clock rule.
- Live stamps use `account`. Bump the engine cache and reducer versions.
- **Revision 6 changes here:** `renew` of a member with no expiry is `malformed`; `revoke.heads`
  are `{namespace, digest}` objects; `shares` and `epochs` are §11.1 epoch objects; coverage is
  granted ⊆ requested; an unknown `serves` value is unknown content; a member added by an
  activation that isn't final has its records held (`authorityBehind`); `policy` gains `rate`.

## Step 5. Calls, links, heads and homes

Files: `v5/speaks.rs` (rewritten as `calls.rs`), `v5/terms.rs`, new `heads.rs`.

- `verify_call`, in exactly the order of §12.3:
  - evaluation at S, with held removals applied;
  - controller-call origin and purpose configuration;
  - the replay store interface (§12.4): a read-only look-up at step 3, then an atomic
    reservation after step 8 and before any effect, keyed with the acting key, retained 7,200 s.
- **Revision 7 changes here:** retention 7,260 s inclusive; step 6 checks bindings before refusals;
  `any:[true, unknown]` is true (only an unknown result is `newerFormat`); a controller must meet
  both forms; removed-and-re-added after S is `refused:revoked`; additions count only after a
  `final` in the held history; a suspension also ends by the clock; members may read history at a
  home with their own key.
- **Revision 6 changes here (the builder's readings, now text):** policy for freshness and quorum
  is the latest held, `callWindow` and `linkMaxAge` the stricter of S and later; a controller must
  pass at S and at its latest state; member expiry against the verifier's clock; link checks link
  by link; three-valued conditions; a suspended controller may call `colophon.history.read`; a
  home accepts its own `colophon.*` purposes; members and homes added by a provisional activation
  are `refused:revoked`.
- Heads: high-water mark, quorum by ancestry, the primary home, equivocation evidence.
- Incremental verification from persisted state.
- Remove `Verdict::Ok { unguarded }` and `Refusal::Stale`; add the reasons in §19.
- The R1/R-A5 history verifier output (guide §4) and persisted state (§17.2).

## Step 6. FFI, WASM and SDKs

Files: `crates/colophon-ffi/src/{lib.rs,keys.rs,types.rs}`, `crates/colophon-wasm/src/{lib.rs,keys.rs}`,
`swift/Sources/ColophonKeys`, `swift/Sources/ColophonKit/Generated`, `sdk/kotlin`, `sdk/android`, `js/src`.

- Export:
  - the history verifier (no host key pair) and the Swift predecessor verifier;
  - the WebAuthn check;
  - call, link, head and receipt prepare and verify;
  - pairing;
  - add-key enrolment with possession and seed transfer;
  - transitions, vetoes and receipts: prepare, verify, and their notices;
  - `renew`, `endSessions`, `resolve`, `successor`, `migration`;
  - the restricted vault HPKE open.
- `ColophonKeys`:
  - set `authorityOrigins` at registration;
  - `user.id` per §17.4;
  - the §17.3 flows.

## Step 7. Homes and the relay

Files: `relay/relay.js`, `relay/server.js`, `relay/README.md`.

- `GET {base}` with `home`.
- `GET`/`POST {base}/authority` with receipts, and 409 and 421 answers.
- Primary-home ordering, and storage only of entries covered by a primary head.
- The 60 s clock rule; the 300 s receipt window.
- `GET`/`POST {base}/pending` with cursors (§14); appending `final`; refusing entries 300 s
  behind the clock; persisting first-seen and serving facts.
- Signing receipts (one per object) and notices; forwarding transitions, vetoes and receipts to
  the other homes; storing an unreceipted `activate` only if seen within its window.
- The rate limit, refused as `malformed`.
- `Authorization: Colophon` with the `colophon.home.*` rules.
- §13.4 applies to `records/authority/*`.

## Step 8. Upgrade and succession tooling

Files: `reference/swift/Sources/ColophonCleanCopy` (refresh `reference/swift/Sources/ColophonAuthority`
from Marginalia `origin/main` first: the reference copy lacks the `layout` kind), `crates/colophon-ffi/src/migration.rs`,
`docs/clean-copy.md`, `docs/app-migration.md`.

- 0.4 in place: the host asks whether every writing app reads 0.5, shows the chosen settings,
  and signs `upgrade`.
- Swift to 0.5. Follow §15.3 and §16.2 in order:
  - preflight under §16.3 (the strict §4.3 DER grammar);
  - appoint the homes, publish the predecessor at `{base}/predecessor/`, and collect the homes'
    genesis receipts within the succession window;
  - wait out the veto window, telling every device that holds an old key;
  - write F only after the due time and with no `successionVetoed`;
  - drain for the window; then write `migration` with `drain`.
- Swift to 0.5, details:
  - build the genesis from the old public keys, collecting possession proofs only for keys
    that aren't carried over;
  - carry roles over exactly (a root library's root to `approve` + `control`, its recovery
    identity to `recover`), and offer §18's reference only as a later transition;
  - collect `handover` (the current root alone for a root library; the control threshold, plus
    recover signers when the recover set changes or its threshold is lowered, for a keyring
    library; every other key at `head` the host can obtain);
  - write the freezing `layout` entry through the Swift `ColophonAuthority` (**blocked until a
    new Apple app version exists**: the shipped Swift code cannot write F; the list of what the
    version must add is in the guide §4 "Writing F from an Apple app", from
    `docs/handoff-engine-05-write.md`: a `successor` member, layout 3 or more, a raw-record append
    or explicit `issued`, a reader rule that F is final for the app that wrote it, and the
    update-required path for old versions);
  - rebuild a slot for every slotted controller, or stop;
  - map roles, custody, operator and caveats, or stop;
  - copy the records;
  - write `migration`.
- Galley's contract §11 and `principal.bind` consume the verified succession and the
  `migration` entry.

## Step 9. Review and freeze

- Independent spec reviews of the final revision (rounds one to five reviewed revisions 1–5).
- An implementation security review.
- Replay of every §21 vector in Rust and in a second language (the TypeScript verifier counts
  as one).
- Performance:
  - WebAuthn verify;
  - cold replay and incremental verification;
  - call verification with three links;
  - the author-chain walk at 50,000 records.
  - the `resolve` look-ahead (checker M5, revision 13, not measured): `resolved_by_activation`
    folds every candidate's branch to its end for each fork the rules leave open, the main fold
    folds the chosen branch again, and `state::apply` builds the list of every held entry on each
    call, so with F resolved forks on a branch of length L over N held entries the work is about
    F·L·N, polynomial and not exponential (no nested look-ahead). A key holder in an account
    without homes can add a fork and resolve pair every few entries, so the cost is
    attacker-controlled; any prior conflict also forces a full replay on every resume. Measure it
    with chained resolves (`prepare_resolve` now builds them) and bound it (cache `by_seq_all`,
    resume past a resolved fork) if the numbers warrant.
- Then the version bump and changelog. None of this is done by the candidate.
