# Handoff: the Colophon 0.5 write side and the account engine

**Spec:** [spec/colophon-0.5.md](../spec/colophon-0.5.md), with the host interface in §17 and
[the guide](../spec/colophon-0.5-guide.md) §4. Implement it **exactly**; the spec decides every
question. If you find an ambiguity, stop and report it. Don't resolve it in code.
**Branch:** `engine-0.5-write`, cut from `spec-0.5` at `02894ef`. Each work package runs in its
own worktree off it and merges back into it.

## Why

`colophon_core::v05` verifies: histories, calls, heads, records, home admission, succession and
the 0.4 upgrade. It writes nothing. Creating an account, changing a keyring, admitting a member,
sealing an epoch, writing a record and syncing still run on the 0.4 `Library` and
`storage::Engine` over `authority::Authority`. No app can run on 0.5 until the core can prepare
every body a host signs, and until an account engine replaces the 0.4 library engine. The
bindings (plan step 6) export what this handoff builds.

## Rules for every package

- New code goes under `crates/colophon-core/src/v05/`. No 0.4 source file changes, and no
  change to `crates/colophon-ffi` or `crates/colophon-wasm`. 0.4 code may be called unchanged
  (`hpke.rs`, `crypto.rs`, `keys::strict_json`, the domain modules).
- The core stays sans-IO with no RNG and no clock: hosts pass seeds and the time.
- No new dependency and no `Cargo.lock` change.
- **Prepare, then finish.** Every action returns exact bytes to sign as steps (path, body,
  signer descriptor, WebAuthn challenge), as 0.4's `SigningStep` and `PendingBatch` do, in new
  0.5 types. `finish` takes the signatures, assembles the envelopes, and runs the 0.5 verifier
  (`v05::history::verify_history`, `calls`, `heads`, `records`) over the result **before**
  returning any record. Nothing is returned on failure. A builder never returns bytes the
  verifier would refuse.
- The builders must not share encoding code with the vector generator
  (`tests/v5_candidate/`), which stays independent.
- **Tests:** each package tests its own module, and proves each builder two ways: its output
  verifies, and it reproduces the matching candidate vector byte for byte from the vector's
  published keys and seeds where one exists. New vectors come from the Rust generator only.
- Report: changed files, commands run with real numbers, and any spec question.

## Work packages

| ID | Wave | Package | Files | Done when |
| --- | --- | --- | --- | --- |
| **E1** | A | **Authority builders.** Genesis (keyring, policy, homes, first slots); the immediate entries `grant`, `renew`, `revoke` (with `kept` and heads), `endSessions`, `rekey`, `keyring`; `vault`; transitions, vetoes and `suspend`; the determined recording entries `activate`, `vetoed`, `final`, `successionVetoed`; `resolve`; equivocation evidence (§8.6, §13.3); possession proofs and cosignatures; rule selection (§8.4: which signers satisfy which rule) | New `v05/build/mod.rs` (step and batch types), `v05/build/authority.rs`; tests `tests/v05_build_authority.rs` | Every builder's output verifies; `rules/equivocation`, `rules/rollback` and `rules/t-activate-identical-bytes` are implemented in the candidate runner |
| **E2** | A | **Vault, slots, pairing and seed transfer under 0.5.** Vault derivation and the `sealed`, `prf` and `combined` slots with 0.5's labels (§7.1, §7.2); rotation when a slotted controller is removed or demoted; pairing (§7.3); moving the seed (§7.4); software identities and kits (§7.5); the restricted vault HPKE open (§17.1) | New `v05/vault.rs`, `v05/slots.rs`, `v05/pairing.rs`; tests `tests/v05_vault.rs` | Unit tests for every slot kind and refusal; `pairing/pairing.json` implemented in the runner; no seed or raw ECDH output crosses the module boundary |
| **E3** | A | **Call-side builders.** Links, calls, heads, receipts and notices (§12, §13); the request body (§9.1) | New `v05/build/calls.rs`; tests `tests/v05_build_calls.rs` | Output verifies under `calls`, `heads` and the home module; the 14 call and 4 head candidate cases reproduce |
| **E4** | B | **Records under 0.5.** Epochs and seals (§11.1), the `/5` operation header (§11.2), author chains, `revoke` with `kept`, proposals and resolutions, legacy `/3` records of an upgraded account behind the §11.5 fence | New `v05/build/records.rs`, additions to `v05/records.rs`; tests | The namespace vectors of plan step V1 item 2 exist and pass; upgraded-account records admit end to end |
| **E5** | C | **The account.** The 0.5 counterpart of `Library`: open from records and persisted verifier state; unlock through slots; every E1–E4 action as `begin_*`/`finish`; merge with change summaries; views, queries and the domain modules unchanged; members, tools and the ledger | New `v05/account.rs` | The 0.4 library test journeys pass when ported to an account: create, add a device, approve an agent, write, revoke, rotate |
| **E6** | C | **The account engine.** The 0.5 counterpart of `storage::Engine`: `RecordSource`, refresh and `apply_paths`, incremental verification from persisted state (§17.2), checkpoints, history pages, blobs, relay cursors against a home (§13, §14) | New `v05/engine.rs` | The 0.4 engine and relay tests pass when ported; cold open and resumed open give the same state |
| **E7** | D | **Upgrade and succession builders.** The 0.4 in-place `upgrade` entry (§16.1); the Swift succession: genesis from old public keys, `handover`, the freezing `layout`, `migration` (§15, §16.2, §16.3) | New `v05/build/upgrade.rs` | The `upgrade/*` and `succession/*` vectors reproduce from their keys |

Wave A's three packages touch disjoint files and run in parallel. The bindings (plan step 6)
start when E5 lands; the relay as a home (step 7) when E6 lands; the upgrade tooling (step 8)
when E7 lands.

## Open at the start

- Spec revision 12 (colophon#7) is in review. It changes `v05/history/` only; packages here add
  new files, and rebase onto it when it merges.
- The checker of the engine did not drive home admission, forged Swift predecessors or the 0.4
  upgrade with tests. E3 and E7 are where that coverage is added.

## What a new Apple app version must do to write F

The builders (`v05/write/succession.rs`) return F as exact Swift-format record bytes (§16.3).
Shipped Swift cannot write them. Paths are Marginalia `packages/Colophon/Sources/`, at
`origin/main` `c8280332`.

1. **A `successor` member on the entry type.** `ColophonAuthority/AuthorityEntry.swift:32-80`
   lists the stored members and has no `successor`; `numbered(_:after:)` (`:93-123`) copies a
   fixed list and would drop it.
2. **A supported layout of 3 or more.** `ColophonAuthority/AuthorityState.swift:56`
   (`supportedStorageLayout = 2`) and `:120-121` (a `layout` above it throws); the writer guard
   at `AuthorityHolder.swift:50-54`. The only layout writers are `AuthorityHolder.swift:35-40`
   and `KeyringHolder.swift:29-34`, both layout 2.
3. **A way to append the exact record bytes the builder returns.** `AuthorityEntry.swift:82-88`
   sets `issued` to `.now` and `numbered` (`:94`) calls that initializer again, so a draft
   re-stamps `issued` and the signatures made over the builder's body no longer match. The app
   needs a raw-record append on `AuthorityLog`, or an explicit `issued` on the draft.
4. **A reader rule that F is final.** Once a `layout` entry carries `successor`, the version that
   writes F must stop writing to that library; with item 2 alone it would keep reading and
   writing after F, which §15.1 calls `malformed` evidence.
5. **Old versions stop with `unsupportedStorageLayout`,** shown as update required: the throw at
   `AuthorityState.swift:120-121`, the message at `ColophonCore/ColophonError.swift:43`, mapped to
   `.updateRequired` at `apps/apple/App/Sync/SharedLibraryDiagnostics.swift:58`. Versions that
   predate `layout` stop with `newerAuthority`. The message says to update the app, which will not
   help for this library; the person must be sent to the successor.

### What a real library still cannot do after the E7 package

- Open its old Swift slots (`sealed` `colophon/sealed-key/1`, `prf` `colophon/vault-prf/1`,
  `combined`) and build the new ones. The genesis builder requires a rebuilt slot for every
  slotted controller, so no real genesis can be built until this exists.
- Copy its records into the successor (opening the Swift namespace keys and re-writing records
  through the drain window). The `migration` entry only reports the counts.
- Sign a veto with an old Swift key (the veto body builder exists; there is no step for a Swift
  descriptor to sign it).
