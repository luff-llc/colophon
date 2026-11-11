# Colophon 0.5: implementation plan

**Status:** plan for the candidate [colophon-0.5.md](colophon-0.5.md), 2026-11-11. No engine
code has been changed for it. Steps are in dependency order; each ends in tests or vectors a
second implementation can run. Paths are relative to the Colophon repository unless stated.
Rules carried over from `docs/handoff-keys-04.md`: the core stays sans-IO with no RNG; no new
Rust dependency (the existing `p256`, `aes-gcm`, `hkdf`, `sha2`, `serde`, `serde_json`, `base64`
suffice); Swift 6 with no third-party dependencies; duplicate JSON names detected by the
existing strict pass, never first- or last-wins.

## Step 0. Decide the existing `v5` module

`crates/colophon-core/src/v5/` and `conformance/0.5/speaks-for`, `conformance/0.5/terms`
implement Galley draft 1 (request with string audience and `body` digest, `unguarded` success,
proof objects, `requires`). They are unused by any binding.

- Keep `terms.rs`'s condition evaluator and its bounds and exact-number comparison; they match
  §10.4. Rework `GrantTerms` to §10.1 (`records`, `services`, no `scope`/`requires`) and the
  narrowing to §10.3.
- Replace `speaks.rs`'s request and proof with §12's link and call, and its order with §12.3.
  Remove `Verdict::Ok { unguarded }` and `Refusal::Stale`; add the §19 call reasons.
- Move the draft-1 vectors to `conformance/0.5/legacy-draft-1/` with a README saying they are
  not 0.5, so nobody mistakes them for the candidate's (the W0 closure asks for exactly this).

## Step 1. Encoding and keys

Files: `keys/strict_json.rs`, `keys/descriptor.rs`, `keys/webauthn.rs`, `keys/envelope.rs`,
`crypto.rs`.

- Canonical re-encoding check for `/5` bodies and canonical base64 (§2.1–§2.2); size bounds
  before allocation (§2.4).
- Descriptor: web origins in `origins`; `authorityOrigins` (§3.1). The WebAuthn verifier takes
  a flag "authority signature" and applies `authorityOrigins` only then (§4.3).
- Export a standalone WebAuthn check returning `{uv}` or `badSignature` plus a diagnostic
  (§17.2; contract R2), and resolve the outcome-name comment in `webauthn.rs`.
- Envelope: `handover` (genesis only); call envelopes with an optional `assertion` and no
  cosignatures.

Tests: unit tests for each new rule, including an `https://` entry with a port, unsorted
`origins`, an `authorityOrigins` entry the descriptor doesn't allow.

## Step 2. Keyring, policy and the add rule

Files: `authority.rs` (keyring types and rules), `slots.rs`, `vault.rs`.

- `Keyring` gains `addThreshold` and `policy` (§6.2–§6.3); bounds of 64 controllers and 256
  slots.
- Rule evaluation order for `keyring`: control, add, recovery (§8.4). Factor the existing
  recovery "only adds" check so both rules share it, extended to `addThreshold` and `policy`.
- Seed transfer (§7.3): `begin_seed_transfer(ephemeral_point)` on the seed holder and
  `finish_seed_transfer` on the new device, with the `colophon/vault-transfer/5` label.
- HPKE open for non-`colophon/` `info` on the unlocked vault (§17.2; contract R10). Refuse any
  `info` starting with `colophon/`.

## Step 3. Authority `/5`, upgrade and succession

Files: `authority.rs`, `model.rs`, `protocol.rs`, `library.rs`.

- A chain may be all `/5`, or `/4` through one `upgrade` entry and `/5` after (§8.1). Replay of
  the `/4` prefix uses today's code unchanged.
- `upgrade` (§16.1): `account` equals the full genesis digest; keyring equality on the 0.4
  fields; not seq 2; at most once. Convert 0.4 grants to terms on replay.
- New kinds `renew`, `endSessions` (with the member rule), `successor`; `revoke` with `member`,
  `kept`, `heads`; `grant` with `terms`; genesis with optional `predecessor`, zero namespaces,
  and no seq-2 rule when there are none.
- `by` must be a controller (or the member for `endSessions`), else `badSignature`, matching
  what 0.4 reports today (`badSignature: foreign controller`).
- Account IDs: store the 64-hex ID; expose the legacy 32-hex prefix for `/3` binding.
- Predecessor checks for `/4` and `/5` histories in Rust. For `colophon/swift-keyring/2`, the
  check lives in `reference/swift/Sources/ColophonCleanCopy` using the reference
  `ColophonAuthority` (`AuthorityState.verifyKeyringChange`, and `root.verify` for a root
  library). The Rust core reports such a predecessor as an unverified claim unless the host
  passes a verified result.

## Step 4. Members, terms and records

Files: `authority.rs` (member table), `library.rs` (admission and folds), `model.rs`,
`records.rs`, `imports.rs`, `domain.rs`, `domains/*`, `engine.rs`, `storage.rs`, `checkpoint.rs`.

- Membership request `/5` (§9.1), coverage of grants by requests (§9.2), import and `serves`
  rules (§9.3), renew shares (§9.4).
- Operation header `/5` with `account`, `level`, `previous` and the new AAD (§11.2). Writers
  keep a per-author, per-namespace chain head and persist it before publishing; restores rebuild
  it from the store.
- Admission (§11.5) with per-namespace access levels, `kinds` and `conditions` after
  decryption, `wrongFormat` for `/3` versus `/5` around the upgrade, and the kept test by
  `kept` digests or `heads` ancestry (§9.5). The ancestry walk is memoized per author and
  namespace.
- Proposals (§11.6): admit `propose` records without folding; fold accepted proposals once at
  the accept's position; list unresolved and declined ones in views. The reducer interface
  gains `acceptedBy` attribution.
- Live stamps use `account` (§11.2); the engine cache version and reducer schema bump so every
  older cache is invalidated (0.3 §7.1 already requires this on format change).

## Step 5. Calls, links and heads

Files: `v5/speaks.rs` (rewritten as `calls.rs`), `v5/terms.rs`, new `heads.rs`.

- Pure `verify_call(call, history, heads, now, audiences, replay_lookup) -> Outcome` with the
  exact order of §12.3; the host passes the replay record lookup and stores results (§12.4).
- `prepare_link`, `prepare_call`, `prepare_head` returning exact bodies.
- `verify_head` with high-water-mark state passed in and returned (§13.3); quorum comparison.
- A pure history verifier returning the R1 view (§17.2), callable with no host identity, and
  able to resume from a persisted verified state.

## Step 6. FFI, WASM and SDKs

Files: `crates/colophon-ffi/src/{lib.rs,keys.rs,types.rs}`, `crates/colophon-wasm/src/{lib.rs,keys.rs}`,
`swift/Sources/ColophonKeys`, `swift/Sources/ColophonKit/Generated` (regenerated by
`scripts/generate-bindings.sh`), `sdk/kotlin`, `sdk/android`, `js/src`.

- Export: history verifier (no `WasmLibrary::new` key pair needed), WebAuthn check, call, link
  and head prepare/verify, upgrade preparation, add-rule passkey enrolment including seed
  transfer, `renew`, `endSessions`, `successor`, vault HPKE open.
- `ColophonKeys`: `user.id` per §17.4; registration with UV required and attestation none;
  the cross-device add flow of §17.3.
- JS: the same, plus `Library.createWith` writing `/5` genesis.

## Step 7. Homes and the relay

Files: `relay/relay.js`, `relay/server.js`, `relay/README.md`.

- `GET {base}/head`, `GET {base}/authority?after=`, `POST {base}/authority` (§14), with the
  home verifying through the WASM build; `Authorization: Colophon <call>` as an alternative to
  bearer tokens. The relay without a home key keeps working as 0.3 §8.

## Step 8. Upgrade and succession tooling

Files: `reference/swift/Sources/ColophonCleanCopy`, `crates/colophon-ffi/src/migration.rs`,
`docs/clean-copy.md`, `docs/app-migration.md`.

- 0.4 in place: a host action that checks every writing app is on 0.5 (by asking the person;
  there is no protocol signal), shows the chosen `addThreshold` and policy, and signs `upgrade`.
- Swift keyring to 0.5: the clean-copy tool targets a `/5` account, builds the genesis keyring
  from the old controllers' public keys, collects `handover` from the old control quorum (or
  root), rebuilds PRF slots with one assertion per credential and sealed slots without one, and
  reports the accounting. It must refuse to run if the old library's `recoverThreshold`
  semantics (the Swift "Two Keys" lowering rule) would be weakened, unless the person confirms.
- Galley's `principal.bind` and the identity service consume the verified succession; they are
  Galley's work, not this repository's.

## Step V. Vectors

Generator: extend `crates/colophon-core/tests/keys_conformance.rs` (or a new
`tests/v5_candidate.rs`) to write `conformance/0.5/` deterministically from published seeds,
with the synthetic authenticator of 0.4. The hand-built `conformance/0.5/candidate/` files must
replay with identical outcomes, or the difference is a spec question to resolve before freeze.

Needed, beyond what `candidate/` has (spec §21 is the full list):

1. Every 0.4 key case as `/5`, and every 0.4 case replayed as the prefix of an upgraded account.
2. Upgrade: `/3` records citing after the upgrade and `/5` records citing before it; a second
   `upgrade`; `/5` before `upgrade`.
3. Add rule: one-signature passkey add; each role cap; policy change refused under it.
4. `authorityOrigins`: authority entry from listed and unlisted origins; call from unlisted.
5. Members: request coverage, per-namespace access, `serves` rules, import rules, renew, revoke
   with `heads` on and off the chain and on a fork, `endSessions` three ways.
6. Records: `/5` headers with AAD, proposals and resolution orders, `kinds`/`conditions`
   refusals reserving budget.
7. Calls: controller call with an assertion; replay identical and conflicting; asOf fork; no
   fresh head; quorum 2 with one stale; revoked and expired members.
8. Heads: equivocation; rollback below a persisted high-water mark.
9. Succession: `/4`, `/5` and Swift predecessors; short handover; unverifiable predecessor.
10. Seed transfer: wrong account and wrong ephemeral key in `info`.

## Step 9. Review and freeze

Two independent read-only spec reviews (as 0.4 had), an implementation security review, the
performance check (WebAuthn verify, cold replay, incremental verification from a persisted
state, call verification with three links), then the version bump and changelog. None of this
is done by the candidate.
