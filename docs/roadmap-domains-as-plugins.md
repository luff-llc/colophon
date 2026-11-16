# Roadmap: domains as plugins

Status: proposal for 0.6, with three small items to settle before the 0.5 freeze. Written
2026-11-15 against `spec-0.5` at `6266d31`. Research only: no code changed.

The concern: podcast, book, saved-item and note logic lives inside `colophon-core`, so
Colophon cannot grow past the apps LUFF writes. The core should hold a standard library only
of what is truly standardized, and everything else should plug in.

## 1. The actual coupling

**Direction.** The coupling runs one way: the 0.5 core calls into the domains, never the reverse.
Nothing under `domains/`, `domain.rs` or `imports.rs` names `v05::`. The domains need only a few
old core types: `model::{MemberKind, OperationView, Grant, time_key}`, `records::{canonical, hex,
digest}`, `blobs::BlobManifest` and `verification::parallel_map`.

**Where `v05/` reaches into the domains:**

| File | What it uses |
| --- | --- |
| `v05/account/action.rs:1471-1488` | `domain::role_allows` (protected kinds by member kind) and `domain::module(ns)…validate_input` before signing a write |
| `v05/engine/live.rs:185-198` | `protocol::live_slot` and the same schema check before a live write |
| `v05/account/derived.rs:11,682,974` | `domain::State::new(ns)`: the fold of every namespace is the domain enum |
| `v05/account/read.rs:6,1030` | `query` calls the domain state; `tools()` walks `domain::NAMESPACES` |
| `v05/account/moving.rs:339,441`, `v05/engine/mod.rs:1654-1683` | `imports::BATCH_KIND`, `ImportBatch` (`Engine::begin_import`) |
| `v05/engine/mod.rs:1245` | `heads_to_retain` works only when `namespace == "listening.podcasts"` |
| `v05/live.rs:198`, `v05/records.rs:1775` | **verifier:** a live-stamped record is refused `invalidPayload` unless `protocol::live_slot` accepts it |
| `v05/swift_copy.rs:41-42,435,631-680` | `ImportState` and `ProjectionState` judge each copied child; one Swift caveat for `playback.naturalEnd.batch` |
| `protocol.rs:117-141` | `live_slot`: only `listening.podcasts` `position` samples (no `seek`; fields limited to `id, show, seconds, duration, seek, expect`) |

The domain names are also hard-coded inside the generic layer itself. `domain.rs:37-49`, the
default `queries()`, matches on the four namespace names. `domain.rs:155-192` holds the module
table and the `ProjectionState` enum. `domain.rs:257-287` lists the protected kinds per
namespace. `domain.rs:314-336` adds playback-order barriers for four podcast kinds.
`imports.rs:205,424,615-660` holds per-namespace category and baseline tables.

**The spec is not domain-free.** The 0.5 spec text names no domain, but §11.8 makes 0.3 §5.1
and 0.3 §6 normative. 0.3 §5.1 says only `listening.podcasts` `position` samples may be live
state. 0.3 §6 carries the kinds table for `reading.saved`, `listening.podcasts` and `notes`.

**Exports.** The 0.5 UniFFI and wasm surface (`crates/colophon-ffi/src/v05/api/`, compiled for the
web by `colophon-wasm` with `web05`) has **no domain-specific types**. A write is
`begin_write(namespace, kind, payload_json)`. Reads are `query_json(namespace, name, args)` and
`tools_json`. An import is `begin_import(namespace, batch_json)`, which takes the generic
`ImportBatch`. The Swift move types (`SwiftChild`, `SwiftBatch` and the rest) are generic too.
Only the legacy 0.3/0.4 FFI is domain-typed: `crates/colophon-ffi/src/migration.rs` exposes the
four 0.1 adapters (`domains/*/import.rs`).

**SDK.** The domain-specific SDK code is already in its own packages. Swift has
`ColophonBooksKit`, `ColophonListeningKit`, `ColophonSavedKit` and `ColophonNotesKit`, generated
from the core schemas by `scripts/generate-swift-domains.py`. Each kit builds a generic
`DomainCommand`. Two small leftovers remain in the generic layers:
- Swift `ColophonSession`: a `reading.saved` initializer (`NamespaceStore.swift:129`) and
  `DomainCommand.capture` (`SessionTypes.swift:67`).
- Android: the same pair in `NamespaceStore.kt:74` and `SessionTypes.kt:60`.

Kotlin and JS are otherwise generic.

**The Swift move.** The app's translator turns old records into children (`SwiftBatch`). The
core then judges each child with the destination domain's validator: `ImportState::validate_batch`
over a scratch `ProjectionState`. So the move needs the four domains present in the engine, and
the translation stays in the app. The 0.1 adapters (`domains/*/import.rs`) serve only the legacy
FFI.

## 2. What an app can do today without touching Colophon

Admission is domain-free (§11.5). An app can write any kind with `begin_write`. The test
journeys show it: `note.put` in `notes` (`tests/v05_e11_calls.rs:271`,
`colophon-ffi/tests/v05_relay_journey.rs:172`, the Kotlin harness) is a free-form kind. The
notes module does not define it, so nothing validates it at write time, and the notes fold skips
it (0.3 §6: unknown kinds are skipped). Blobs (`colophon.blobPublish`, `colophon.blobReference`)
and proposals work in any namespace. An app reads its records back through `view(ns).admitted`
or `history(ns, offset, limit)` and folds them itself.

**What it loses without a domain module:**
- validation at write time;
- a fold, conflict handling (`expect`, alternatives) and `invalid` lists;
- named queries and indexes;
- the encrypted, incremental checkpoint of its state;
- agent tools;
- import validation;
- live state.

**Where the core refuses or special-cases a kind it does not know:**
- **Live state.** Only podcast positions may be live; any other live-stamped record is refused
  `invalidPayload` by every replica (`v05/live.rs:198`, `v05/records.rs:1775`).
- **Namespaces are fixed at genesis.** A `rekey` naming an undeclared namespace is `malformed`
  (`v05/history/state.rs:2810`), and a grant must name a declared namespace
  (`v05/members.rs:320`). No authority kind adds one. An app cannot bring a new namespace to an
  existing account. This includes the zero-namespace identity accounts of changes #23.
- **Name collisions.** Writing free-form kinds into another domain's namespace works today. It
  would silently change meaning the day that domain defines the same kind name.
- **Payload versions.** Any payload with `v` ≠ 1 is admitted but never folded
  (`v05/records.rs:1800`). Live records also require `v` = 1.

## 3. What a domain module is today

| Part | Example | Must it run in the engine? |
| --- | --- | --- |
| Kind names, payload schemas | JSON Schema specs; books and saved also use code validators (`x-colophon-books-kind`, `x-colophon-saved-command`, `domain.rs:96-101`) | No. Checking before signing is a courtesy, and admission ignores the result. |
| Fold, derived state, conflicts | LWW in `(clock, author, id)`, `expect` → `conflicts`, tombstones, `extensions` bag, reference rules (a note needs its notebook) | For speed and cross-platform agreement: one Rust implementation behind every SDK. Verdicts don't depend on it, so it could live in the app. |
| Role fences | `setCopyLoan`, `reviewProposal`, saved protected kinds (`domain.rs:257-287`) | No. Grant `kinds` and `conditions` (§10.1, §10.4) are the protocol's generic fence. |
| Queries and indexes | `saved/item_index.rs`, `order_index.rs`, paged lists, counts, search | For speed (state stays in the engine). |
| Import validation | identity categories, baseline kinds (`imports.rs:615-660`), `validate_batch` | The `importBatch` envelope is protocol (0.3 §7.2, normative) and must stay. The per-domain tables can be plugged in. |
| Translation from old formats | 0.1 adapters (`domains/*/import.rs`); the Swift translator | No. The Swift translator already runs in the app. |
| Evidence | `listening/evidence.rs` | No. It is a fold-side view of import evidence. |
| Live rule | `protocol::live_slot`, `heads_to_retain`, playback barriers | **Yes.** It decides verdicts, so every replica must agree. |
| Ledger phrases, tool specs | `write_phrase`, `contribution_names`, `Spec` | No. This is display data. |

Only the live rule is part of the protocol. Everything else is local derived state.

## 4. Plugin designs

**(a) Packaging.** Move `domains/`, the domain half of `domain.rs` and the import tables into
`colophon-domain-{books,listening,notes,saved}` crates. They implement one `Domain` trait:
specs, validate, new state, apply, query, import hooks and an optional live rule. The core holds
a registry instead of `match namespace` and `enum ProjectionState`.

- **Cost:** about 13,600 lines move (domains 12,590, `domain.rs` 367, part of `imports.rs`). About
  12 call sites in `v05/` are rewired, plus `protocol.rs` and the legacy `engine.rs`,
  `library.rs`, `storage.rs` and `ffi/migration.rs`. The checkpoint's reducer serialization
  changes, which is a local cache: bump `REDUCER_SCHEMA`.
- **SDK impact:** none, if `colophon-ffi` enables all four domains by default, because the
  exports are JSON.
- **What it forbids:** nothing. It also adds nothing for outsiders: a third-party domain still
  needs a custom build of the FFI binary.

**(b) Declarative domains.** An app registers its domain as data and the engine interprets it.
Judged from the four domains, the description must express:
- collections keyed by `id` in named categories;
- per-kind effects: create, upsert fields, replace an ordered list, tombstone;
- reference checks (a note needs its notebook; no edit moves a note across notebooks);
- LWW with `expect` conflicts and alternatives;
- monotonic rules (a passive position only advances unless `seek`);
- member-kind fences;
- small state machines (consumption states, proposal review, ask/answer/accept jobs);
- paged, filtered and sorted queries with counts;
- import categories.

Notes and most of books fit. Saved's search, sort and feeds, and listening's smart playlists,
segments and transcript jobs do not without escape hatches.

- **Cost:** a language, an interpreter, vectors for it in every implementation, and a
  versioning story. This is large.
- **What it forbids:** arbitrary logic.
- **What it gives:** deterministic folds by construction, review as data, and no rebuild for a
  new domain.

**(c) Code plugins.**
- **Host callbacks** (a Swift or Kotlin fold called from Rust) are rejected: they are
  nondeterministic across platforms, slow over FFI, and break the "one implementation" property.
- **WASM components per domain** remain the option. The guide §6 already lists "modules as
  published WASM" as future work.
  - **Determinism:** good with NaN canonicalization, no host imports, and fuel and memory limits.
  - **Binary size:** iOS forbids JIT, so the engine needs an interpreter (wasmi, around 1-2 MB)
    and accepts slower folds. The browser can use its own engine.
  - **FFI surface:** a loader, plus a module identity pinned in the account (by digest), so
    every replica folds with the same code.
  - **Review:** a sandboxed module can only spoil its own namespace's view, never verdicts.
    Choosing and updating module versions becomes a product problem.

**What "truly standardized" means.** A schema belongs in the standard library only if:
1. at least two independently built apps write it and read each other's records;
2. it has a written spec and conformance vectors;
3. its owner commits to additive-only change.

Things the protocol itself needs always qualify: the `colophon.*` engine kinds (`importBatch`,
`blobPublish`, `blobReference`, `accept`, `decline`, `resolveHistorical`), `basis`, the common
blob and import queries, and the generic `expect` and `extensions` conventions.

None of the four domains qualify today. Each is one product's schema. `listening.podcasts` and
`reading.saved` carry about 30 kinds each, with transcripts, AI answers, magazine subscriptions
and playlists. Later candidates are the three-kind notes core and the saved `capture` from the
0.3 §6 table, and perhaps a generic "progress" live primitive, once a second app adopts them.

## 5. Inside 0.5, and what waits for 0.6

**Step (a) is not for 0.5.** It needs no SDK change, but it moves about 13,600 lines and rewires
the reviewed write, fold and live paths just before the independent security review (freeze
condition 5). The gain is internal only.

**Settle before the freeze**, so that 0.6 plugins need no migration and no forced upgrade:

1. **Adding namespaces after genesis (wire).** If 0.6 adds a namespace with a new authority kind,
   every 0.5 replica stops at it (`newerFormat`, §8.5 step 4). If 0.6 does it with a `rekey`,
   every 0.5 replica reads that `rekey` as `malformed`. Either way, the first app to bring its
   own namespace forces every device to upgrade.
   - **Proposed rule:** a `rekey` that introduces epoch 1 for a valid name not yet declared
     declares it, within the 64 cap, signed under the existing `rekey` rule and sealed to the
     vault.
   - **Cost:** the check at `history/state.rs:2810`, dynamic namespace lists in the derived
     state, one §8.2 sentence and two vectors.
2. **Live state for any kind (verdict).** Restate 0.3 §5.1's scope as "the `(namespace, kind)`
   pairs whose module defines a live rule; in 0.5 only `listening.podcasts` `position`". Then a
   live candidate whose `(namespace, kind)` or `v` the reader has no rule for becomes
   `newerFormat`, not `invalidPayload`.
   - **Cost:** two code sites (`v05/live.rs:198`, `v05/records.rs:1775`), one sentence and one
     vector. There are no live vectors yet.
   - **Unchanged:** the podcast slot derivation.
   - **Why:** verdicts are re-judged by newer readers, so this is not data loss. It stops 0.5
     devices from calling a 0.6 app's state corrupt.
3. **Spec scope and names (text only).** In §11.8, keep 0.3 §6's generic rules but mark its
   namespace table, and 0.3 §5.1's podcast specifics, as the reference implementation's built-in
   modules rather than conformance. Then a second implementation need not implement podcasts.
   Also:
   - reserve kinds and namespaces beginning `colophon.` (today only purposes are reserved, §12.2);
   - state that a record's `kind` follows the §10.1 kind grammar, so a grant can always name it;
   - recommend that new app-owned namespaces use a reverse-DNS name (it already fits the
     namespace grammar), with bare names kept for the standard library and the four existing
     names grandfathered;
   - say that free-form kinds belong in the app's own namespace.

**Waits for 0.6:**
- step (a);
- per-domain reducer versions in the checkpoint;
- passing `v` to the module;
- moving the Swift and Android `reading.saved` conveniences into `ColophonSavedKit`;
- generating the kits from the registry;
- any decision on (b) or (c).

## 6. Recommendation

1. Move no code in 0.5. Admission already ignores domains, so splitting them later changes no wire format.
2. Before the freeze, fix the two protocol-level couplings: namespaces can be added after genesis, and live state is not limited to podcasts.
3. Edit §11.8 so the domain table and podcast live scope are built-ins, not conformance, and reserve `colophon.` names.
4. In 0.6, do (a): domain crates behind a registry, all four on by default in the FFI, no SDK change. Choose (b) or (c) only when a third-party app needs it.
5. Standard library = the protocol's `colophon.*` kinds and conventions; promote a domain only when a second independent app interoperates on it.

**Mike's decisions:**
- Allow adding namespaces after genesis in 0.5 (verifier rule, vectors before freeze), or accept a forced upgrade later.
- Make unknown live candidates `newerFormat` in 0.5.
- Demote the 0.3 §6 table and the §5.1 podcast scope from conformance.
- Naming: reverse-DNS for app-owned namespaces, bare names for the standard library?
- Whether third-party (non-LUFF) domains are a goal at all. If yes, (b) or (c) belongs on the 0.6 or 0.7 plan; if no, (a) is enough.
