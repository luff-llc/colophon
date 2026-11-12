# Colophon 0.5: implementation plan

**Status:** plan for [colophon-0.5.md](colophon-0.5.md), revision 2, 2026-11-11. No engine code
has been changed for it. Steps are in order. The vectors come first, because §21 says the
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
  `conformance/0.5/candidate/` (built by `generate.py` and `rules.py`) into it, so one generator
  owns them all. The ported files must come out byte-identical, or the difference becomes a
  spec question.
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
  3. Rotating keyring changes: removing or demoting a slotted controller, and cancelling a
     slotted recovery addition.
  4. Seed transfer under the pairing scheme.
  5. Calls with two homes and one stale head; additions after S ignored.
  6. `/5` succession with fresh predecessor heads; the migration entry with real view digests.
- **Also:** move the draft-1 vectors (`conformance/0.5/speaks-for`, `conformance/0.5/terms`) to
  `conformance/0.5/legacy-draft-1/`, update `tests/v5_conformance.rs` to read them there, and say
  in a README that they aren't 0.5.

## Step 1. Encoding, keys and origins

Files: `keys/strict_json.rs`, `keys/descriptor.rs`, `keys/webauthn.rs`, `keys/envelope.rs`,
`crypto.rs`.

- Canonical re-encoding check for `/5` bodies; canonical base64 including padding bits; strict
  calendar dates with exactly three fraction digits; bounds before allocation (§2).
- Descriptor: web origins in `origins`; `authorityOrigins`.
- WebAuthn verifier: an `authority` flag that applies the authority-origin rule (§4.3); a call
  path that takes the verifier's configured call origins; flags and counter policy.
- Envelope: `additions`, `handover`; call envelopes with an optional `assertion`.
- Export the standalone WebAuthn check (contract R2).

## Step 2. Keyring, policy and rules

Files: `authority.rs`, `slots.rs`, `vault.rs`.

- `Keyring` gains `addThreshold`, `countBy` and `policy`; controllers gain `holder`, `audiences`,
  `until` and role `sign`; bounds of 64 controllers and 256 slots.
- Rule evaluation (§8.4), in this order: control, add, recovery, cancel. Then possession and the
  recovery-set rule. Counting is by keys or holders. The control rule counts the larger
  threshold. Delayed and provisional signers count for nothing. Factor the "only adds" check
  out and share it.
- Recovery-added tracking with the receipt time, and the delay computation.
- Rotation only for controllers some slot ever named (§8.3). Re-adding a removed controller.
- Seed transfer (§7.4) and pairing (§7.3): `begin_pairing`, `reveal`, `pairing_code`.
- The restricted vault HPKE open (§17.2).

## Step 3. Authority `/5`, forks, upgrade and succession

Files: `authority.rs`, `model.rs`, `protocol.rs`, `library.rs`; new `swift_predecessor.rs`.

- Chains: all `/5`, or `/4` through one `upgrade` then `/5`.
- Monotonic `issued`; future entries held.
- Kinds:
  - new: `renew`, `endSessions`, `resolve`, `migration`, `successor` (terminal);
  - changed: `revoke` (`member`, `kept`, `heads`), `grant` (`terms`), and genesis (optional
    `predecessor`, zero namespaces).
- Fork detection across held branches, and `resolve` (§8.6).
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

## Step 5. Calls, links, heads and homes

Files: `v5/speaks.rs` (rewritten as `calls.rs`), `v5/terms.rs`, new `heads.rs`.

- `verify_call`, in exactly the order of §12.3:
  - evaluation at S, with held removals applied;
  - controller-call origin and purpose configuration;
  - the replay store interface (§12.4): an atomic record-before-effect, keyed with the acting
    key, retained 7,200 s.
- Heads: high-water mark, quorum by ancestry, the primary home, equivocation evidence.
- Incremental verification from persisted state.
- Remove `Verdict::Ok { unguarded }` and `Refusal::Stale`; add the reasons in §19.
- The R1/R-A5 history verifier output (§17.2).

## Step 6. FFI, WASM and SDKs

Files: `crates/colophon-ffi/src/{lib.rs,keys.rs,types.rs}`, `crates/colophon-wasm/src/{lib.rs,keys.rs}`,
`swift/Sources/ColophonKeys`, `swift/Sources/ColophonKit/Generated`, `sdk/kotlin`, `sdk/android`, `js/src`.

- Export:
  - the history verifier (no host key pair) and the Swift predecessor verifier;
  - the WebAuthn check;
  - call, link, head and receipt prepare and verify;
  - pairing;
  - add-key enrolment with possession and seed transfer;
  - recovery with the delay, and cancel;
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
- The ±60 s and ±300 s clock rules.
- Signing receipts and notices.
- `Authorization: Colophon` with the `colophon.home.*` rules.
- §13.4 applies to `records/authority/*`.

## Step 8. Upgrade and succession tooling

Files: `reference/swift/Sources/ColophonCleanCopy` (refresh `reference/swift/Sources/ColophonAuthority`
from Marginalia `origin/main` first: the reference copy lacks the `layout` kind), `crates/colophon-ffi/src/migration.rs`,
`docs/clean-copy.md`, `docs/app-migration.md`.

- 0.4 in place: the host asks whether every writing app reads 0.5, shows the chosen settings,
  and signs `upgrade`.
- Swift to 0.5:
  - build the genesis from the old public keys, collecting possession proofs only for keys
    that aren't carried over;
  - collect `handover` (the recovery identity for a root library; recover signers when the
    recovery threshold is lowered);
  - write the freezing `layout` entry through the Swift `ColophonAuthority`;
  - rebuild a slot for every slotted controller, or stop;
  - map roles, custody, operator and caveats, or stop;
  - copy the records;
  - write `migration`.
- Galley's contract §11 and `principal.bind` consume the verified succession and the
  `migration` entry.

## Step 9. Review and freeze

- Two independent spec reviews of revision 2.
- An implementation security review.
- Replay of every §21 vector in Rust and in a second language (the TypeScript verifier counts
  as one).
- Performance:
  - WebAuthn verify;
  - cold replay and incremental verification;
  - call verification with three links;
  - the author-chain walk at 50,000 records.
- Then the version bump and changelog. None of this is done by the candidate.
