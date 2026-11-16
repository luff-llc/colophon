# Roadmap for 0.6: modules and composition

Status: **planned for 0.6, not decided.** Written 2026-11-15 against `spec-0.5` at `25027b0`.
Nothing here goes into 0.5 and nothing is built. 0.5 ships as the freeze package designs it.

The only part that matters for 0.5 is §A: what 0.5 must have so that 0.6 arrives as an in-place
upgrade, not a migration. The rest is a plan. Where it names freeze streams (W2-R, W3-G) or "0.5",
read that as "the 0.6 equivalent, after 0.5 ships". The spec changes it describes (§3) would be
0.6 text.

Sources: the domains survey (`docs/roadmap-domains-as-plugins.md` on `docs-0.6-domains`), the
freeze package ([`design-freeze-package.md`](design-freeze-package.md)), and the code at the base
commit.

## A. What 0.5 must have so this arrives as an in-place upgrade, not a migration

**Short answer: the layout door, plus data already written staying readable. Nothing in 0.5's data
on disk would block the move.** But two more freeze items are needed, not just the door, and two
small hazards exist.

**The freeze items 0.6 depends on.** All three are already in the freeze package; keep them as
designed.

1. **F1: unknown content is `newerFormat`.** This lets 0.6 add record kinds, payload versions and
   the `colophon.module` record (§4.3) without the door. 0.5 readers then say "update me" for those
   records only. Most of 0.6's module work arrives this way, not through the door.
2. **F5: namespaces declared after genesis, by `rekey`.** Without it, the first 0.6 app that brings
   its own namespace would stop every 0.5 device. With it, a module's namespace is an ordinary
   declaration.
3. **F5's live rule: a live candidate whose `(namespace, kind)` or `v` has no rule is
   `newerFormat`, never `invalidPayload`.** This lets 0.6 open live state to any module while 0.5
   readers say "update me". If 0.5 called such candidates `invalidPayload` instead, a 0.5 reader
   would refuse what 0.6 admits, which is an older reader deciding differently. That could be
   fixed only after the door.
4. **F3: the layout door.** It is needed only for a 0.6 change that 0.5 readers would judge
   differently. In this plan there is one such change, below.

**Checked against what 0.5 writes to disk:**

| What is on disk | Can a 0.6 module design absorb it in place? |
| --- | --- |
| Record paths `ops/`, `state/`, `history/` `<author>/<namespace>/…` | Yes. They are generic and name no subject |
| Header fields (§11.2 stable fields), plaintext `{id, kind, v, clock, authority, created, payload}` | Yes. Generic. A module reads `kind`, `v` and `payload` |
| The live slot derivation (SHA-256 hex of the payload's `id`) | Yes. The generic rule of §0 is exactly this derivation, so every existing slot name stays valid |
| Blob manifests and `colophon.blobPublish` / `blobReference` | Yes. These are core kinds, not tied to a module |
| `colophon.importBatch` and its children | Yes. The envelope is core; the children fold in the same built-in modules |
| Namespaces declared at genesis, under bare names (`notes`, `reading.saved`, `reading.books`, `listening.podcasts`) | Yes. A module claims exact names, so the built-ins claim the four grandfathered names (§4.1) |
| Grants naming namespaces and `kinds` | Yes. Generic |
| Device checkpoints (folded state) | Yes. They are a local cache and rebuild once |

**What could NOT be absorbed in place:** nothing in the data. One verdict and two hazards need
care.

1. **The live `seek` verdict.** 0.5's one-entry registry refuses a podcast live `seek`
   (`invalidPayload`). §0's generic rule would make that `seek` the slot head. That is a verdict
   change, not "update me". So 0.6 does one of two things:
   - keeps that refusal as a frozen rule for that one entry; or
   - makes the change only after an account raises its layout.
   No data is affected: no writer produces a live `seek`. Default: keep the refusal frozen, and
   apply the generic rule to every other `(namespace, kind)`.
2. **`colophon.module` arriving in 0.6.** A 0.5 reader judges it `newerFormat`. Under §11.6 rule 3,
   any later proposal in that namespace would then be unresolved for 0.5 readers until they
   update. That is "update me", not a migration. Defining the kind in 0.5 (a shape check, no fold)
   would avoid it. It is optional and cheap; the owner's call.
3. **Free-form kinds written into another module's namespace.** Today's tests write `note.put`
   into `notes`. If a module later defines the same kind name, old records silently take the new
   meaning. 0.5 already says free-form kinds belong in the app's own namespace (§11.8). Keep that
   rule, and keep real data out of the four built-in namespaces under undefined kinds.

**The one idea.** The protocol judges records without knowing what they mean. A **module** gives
records meaning on the replicas that have it. No protocol verdict ever depends on which modules a
replica has. Two replicas, one with a module and one without, agree on every verdict and every
live head. They differ only in what they can show.

## 0. The generic live rule (0.6)

0.5 builds a normative live-rule registry with one entry (podcast `position`). In 0.6 a generic
live rule would replace it, except for the frozen `seek` refusal (§A item 1). The table below was
written as an instruction to the freeze stream W2-R; it now describes the 0.6 work.

| # | W2-R builds | Replaces in the freeze design |
| --- | --- | --- |
| 1 | `protocol.rs`: `live_slot(payload) -> Option<String>`. The slot is the lowercase SHA-256 hex of the payload's `id`, a string of 1–256 bytes. This is today's podcast derivation, so no slot name changes. | `live_rule(namespace, kind, v) -> {Slot, Refused, Unknown}` (§5.3) |
| 2 | `live.rs::judge_one` and the retained-copy check in `records.rs` (`:1777`) use it. No check of namespace, kind, `v`, `seek` or the payload's other fields. A missing or bad `id`, or a stamp slot that differs, is `invalidPayload`. | `Unknown` → `newerFormat`; `seek` → `invalidPayload` |
| 3 | The podcast predicate (kind `position`, `v` 1, no `seek`, the six allowed fields) moves to a new file `domains/listening/live.rs` as that module's live rule. `engine/live.rs:185` calls it (one line; that file belongs to no freeze stream). It decides what the writer offers and what the fold shows, never a verdict. | the registry entry |
| 4 | The engine kind `colophon.module` is defined (§4.3). The core checks its shape only and folds nothing. A bad shape is `invalidPayload`. | — (it would otherwise be an unknown `colophon.` kind, `newerFormat`) |
| 5 | `Judged` records the payload `v`. Folding is unchanged for now: `folded` still means `v` = 1. Stream M2 hands `v` to the module. | — |

Vectors (in `cases_freeze_records.rs`, `conformance/0.5/candidate/records/`). They replace the five
live rows of the freeze design §5.4:

| Vector | Expected | Freeze design said |
| --- | --- | --- |
| `records/f5-live-podcast-position` | the slot's current head | same |
| `records/f5-live-seek-is-head` | current head (the podcast fold lists it as `invalid`) | `invalidPayload` |
| `records/f5-live-unknown-kind` (a kind in an app namespace) | current head | `newerFormat` |
| `records/f5-live-unknown-v` | current head | `newerFormat` |
| `records/f5-live-no-id`, `-id-not-string`, `-id-257-bytes`, `-id-mismatch` | `invalidPayload` | — |
| `records/f5-live-retained-id-mismatch` (an `ops/` copy) | `invalidPayload` | — |
| `records/f5-live-colophon-kind-unknown` | `newerFormat` (the general `colophon.` rule) | — |
| `records/f5-live-caveated-other-kind` | `caveatedLive` | — |
| `records/m-module-record`, `records/m-module-record-bad-shape` | admitted; `invalidPayload` | — |

**Existing vectors that change: none.** There are no live vectors yet, and no 0.5 vector holds a
podcast payload.

**Why replicas cannot disagree.** The live verdict reads the header, the stamp, the grant, the
epoch, the clock and the payload's `id`. All of these are generic and every replica that holds the
epoch key reads them the same way. Which candidate is the head depends only on generation order and
equivocation, which are generic too. A module reads the head afterwards and decides only what to
show. A home never opened payloads, so it behaves exactly as before.

**What it loosens, on purpose.** Today a live `seek` is refused and the previous head stays. After
this change the `seek` becomes the head, and the podcast module shows the highest earlier candidate
it holds instead. The home already behaved this way (it cannot open payloads), and the writer is an
uncaveated member who could write any position anyway. No authority or budget rule depends on it:
a live writer must be uncaveated (no `kinds`, `writes`, `expires` or `conditions`), so liveness
cannot carry a kind past a grant's fence.

**The promise later versions keep** (spec §11.9). The live verdict stays generic. A later version
never refuses a live candidate for its namespace, kind, `v` or payload beyond `id`. If one must, it
raises the layout first (§20).

## 1. What a module is

A module is everything one app's subject matter needs from Colophon, behind one interface. It has
an identity (`id`, `rules`), the namespaces it owns, and the parts below.

| Part | What it is | Same on every replica? |
| --- | --- | --- |
| Identity | `id` (reverse-DNS), `rules` (an integer that only goes up) | Yes: it names the rules |
| Namespaces | The exact names it owns. Declared in an account by F5's `rekey`. | Names: yes (protocol). Which module owns a name: the module says; two modules claiming one name is refused when the registry is built |
| Kinds and payload versions | The `(kind, v)` pairs it understands, each with an input schema | Yes, per `rules`. Additive only |
| Validation at write | Checks a payload before the host is asked to sign | No: a courtesy. Admission ignores it. It SHOULD match the fold's own checks |
| Fold | Admitted records, in fold order, become derived state | Deterministic and versioned. It decides no verdict, so it is a display agreement, not a protocol one |
| Role fences | Kinds only an app or device member may write | Deterministic, part of the fold. The protocol's own fence is a grant's `kinds` |
| Queries | Named reads of derived state, with JSON in and out | Deterministic per `rules`; which ones an app calls is local |
| Indexes | Structures that make queries fast | Local (derived from the fold) |
| Live: slot derivation | — | Not the module's. The protocol fixes it (payload `id`) |
| Live: which kinds may be live | The kinds and versions the module offers and folds as live | Deterministic per `rules`. Writer and fold only |
| Live: how candidates supersede | The protocol picks the head. The module may skip a head it does not accept and show the highest earlier candidate it holds | Head: protocol. Fallback: deterministic over what is held (which already depends on arrival, §11.8 "Limit") |
| Live: retention | Which slots a durable write cites, so the writer retains their heads first | Writer only. Default: the slot of the payload's `id` |
| Blobs | Which payload fields name blobs; whether they are required | The blob kinds are protocol. The field list is local |
| Import | Identity categories, which kinds create an identity, child validation for `colophon.importBatch` | Deterministic (fold side). The batch envelope stays protocol (0.3 §7.2) |
| Translation from older data | Old app data becomes children of an import batch | Local: it runs in the app (the Swift move already does this) |
| Evidence | Views over import evidence and history | Deterministic, fold side |
| Display | Display name, ledger phrases, contribution names, tool descriptions | Local |

The rule of thumb: **nothing a module does is a verdict.** What must be the same everywhere is
either protocol (and generic) or fold (deterministic within one `rules` version).

## 2. The seam in the core

### 2.1 The interface

A Rust trait and a registry handed to the engine when it is built. Everything that crosses the seam
is data: strings, JSON values and bytes. No module type appears in the core's signatures. That is
what lets a declarative module or a WASM component sit behind the same seam later (§7).

```rust
// crates/colophon-core/src/module/mod.rs (new)
pub struct Manifest {
    pub id: String,                // reverse-DNS; `colophon.` reserved for the core
    pub rules: u32,                // goes only up; what "update me" compares
    pub reducer_schema: u32,       // local cache generation; bump to rebuild checkpoints
    pub namespaces: Vec<String>,   // exact names owned
    pub display_name: String,
    pub kinds: Vec<KindSpec>,      // name, versions, input schema, live, protected, phrases
    pub queries: Vec<Spec>,        // name, description, input schema
}
pub struct Admitted<'a> {          // one admitted record, as the fold sees it
    pub op: &'a OperationView,     // id, kind, author, clock, created, payload
    pub v: u64,
    pub author: &'a AuthorContext, // from verified authority, never from the payload
    pub live: bool,                // a live head, not a durable record
    pub baseline: bool,            // an imported baseline child
}
pub trait Module: Send + Sync + 'static {
    fn manifest(&self) -> &Manifest;
    fn new_state(&self, namespace: &str) -> Box<dyn ModuleState>;
    fn restore(&self, namespace: &str, bytes: &[u8]) -> Option<Box<dyn ModuleState>>;
    fn check_write(&self, namespace: &str, kind: &str, payload: &Value, author: MemberKind)
        -> Result<(), String>;                       // courtesy, before signing
    fn live_write(&self, namespace: &str, kind: &str, payload: &Value) -> bool;
    fn cited_slots(&self, namespace: &str, kind: &str, payload: &Value) -> Vec<String>;
    fn import_identity(&self, namespace: &str, kind: &str, payload: &Value)
        -> Option<Identity>;                         // category, creates
}
pub trait ModuleState: Send + Sync {
    fn apply(&mut self, record: &Admitted<'_>);      // unknown kind or v: count it, skip it
    fn query(&self, name: &str, args: &Value) -> Result<Value, String>;
    fn identity_exists(&self, category: &str, id: &str) -> bool;
    fn counts(&self) -> Counts;                      // newer, invalid
    fn save(&self) -> Vec<u8>;                       // for the sealed checkpoint
    fn clone_box(&self) -> Box<dyn ModuleState>;
    fn bind_prefix(&mut self, _digest: &str) {}
    fn can_insert_retained(&self, _r: &Admitted<'_>) -> bool { false }
}
pub struct Registry { /* modules, and namespace -> module */ }
impl Registry {
    pub fn empty() -> Self;
    pub fn with(self, m: Arc<dyn Module>) -> Result<Self, String>; // a duplicate id or namespace is refused
    pub fn module_for(&self, namespace: &str) -> Option<&dyn Module>;
    pub fn manifests(&self) -> Vec<&Manifest>;
    #[cfg(feature = "modules-builtin")] pub fn builtin() -> Self;    // the four
}
```

The core keeps its own fold of the `colophon.*` engine kinds (blobs, import batches, historical
resolution, `colophon.module`), which today is `imports::ImportState`. A namespace's derived state
becomes `NamespaceFold { core: CoreFold, module: Option<Box<dyn ModuleState>> }`. A namespace
with no module still gets the core fold: blobs, import receipts and the `colophon.module` record
work everywhere.

Where the registry enters: `EngineOptions` gains `registry: Arc<Registry>`, and `Account::open`
and `Account::create` take it. The FFI's engine constructor passes the registry its features build
(§6). The checkpoint stores, per namespace, `(module id, rules, reducer_schema, bytes)`. A mismatch
on any of the three replays that namespace only. The global `REDUCER_SCHEMA` covers the core fold
alone.

### 2.2 Every call site, and what it becomes

| # | Site (at `25027b0`) | Today | Becomes | Stream |
| --- | --- | --- | --- | --- |
| 1 | `v05/records.rs:1778` | `protocol::live_slot(ns, kind, payload)` on a retained live copy | `protocol::live_slot(payload)` | W2-R |
| 2 | `v05/live.rs:196-201` | `v` = 1 and the podcast slot, else `invalidPayload` | generic slot only | W2-R |
| 3 | `protocol.rs:117-141` | the podcast predicate | generic `live_slot`; the predicate goes to `domains/listening/live.rs` | W2-R |
| 4 | `v05/engine/live.rs:185` | podcast slot, or "not live state" | generic slot, and `module.live_write` when a module owns the namespace | W2-R (one line), then M1 |
| 5 | `v05/engine/live.rs:191-197` | `domain::module(ns)` + `validate_input` | `module.check_write` | M1 |
| 6 | `v05/engine/mod.rs:1240-1270` `heads_to_retain` | only when `namespace == "listening.podcasts"` | any namespace: the slot of the payload's `id` plus `module.cited_slots` | M1 |
| 7 | `v05/engine/mod.rs:1654-1683` `begin_import` | `imports::ImportBatch`, `BATCH_KIND` | unchanged: a core kind; the type moves to `module::core` | M1 |
| 8 | `v05/account/action.rs:1449-1458` | `domain::role_allows` | `module.check_write(.., author kind)` | M2 |
| 9 | `v05/account/action.rs:1459-1466` | `domain::module(ns)` + `validate_input` | the same call as row 8 | M2 |
| 10 | `v05/account/derived.rs:682`, `:974` | `domain::State::new(ns)` | `NamespaceFold::new(&registry, ns)` | M1 shim, M2 threads the registry |
| 11 | `derived.rs:1289,1301,1348`; `account/mod.rs:1100,1628` | serde of the `ProjectionState` enum | per-namespace `save()` bytes with module id, `rules`, `reducer_schema` | M2 |
| 12 | `v05/account/read.rs:1022-1046` `tools()` | walks `domain::NAMESPACES` (the four constants) | walks the account's declared namespaces, then `registry.module_for` | M2 |
| 13 | `read.rs:1030` | `imports::query_specs()` | the core fold's queries (unchanged names) | M2 |
| 14 | `read.rs:1038` | `domain::role_allows` | `KindSpec.protected` | M2 |
| 15 | `read.rs:1213` | `write_phrase` | `KindSpec` phrase | M2 |
| 16 | `v05/account/moving.rs:339`, `:441` | `BATCH_KIND` | unchanged (core kind) | — |
| 17 | `v05/swift_copy.rs:41-42`, `:633-690` `Scratch` | `ImportState` + `ProjectionState` | `NamespaceFold` from the registry; a destination with no module refuses its children, as today | M1 |
| 18 | `v05/swift_copy.rs:435` | podcast `playback.naturalEnd.batch` caveat | **stays.** It reads the shipped Swift format's own admission rule (§16.3, frozen legacy). It is the one place a subject name stays in `v05/`, and it is labelled so | — |
| 19 | `imports.rs:205` | notes `validate_payload` for import children | `module.check_write` inside batch validation | M1 |
| 20 | `imports.rs:424` | `reading.saved` role fence in the batch fold | `KindSpec.protected` | M1 |
| 21 | `imports.rs:612-665` | `creates_identity`, `identity_category` tables | `module.import_identity` | M1 |
| 22 | `domain.rs:37-49` | default queries by namespace name | each module's `Manifest.queries` | M1 |
| 23 | `domain.rs:155-245` | `module()`, `NAMESPACES`, `ProjectionState` enum | `Registry` and `NamespaceFold` | M1 |
| 24 | `domain.rs:251-288` | `role_allows`, protected kinds per namespace | `KindSpec.protected` | M1 |
| 25 | `domain.rs:289-367` | podcast playback barriers in the generic `State` | inside the podcast module's state | M1 |

The legacy 0.3/0.4 surfaces (`engine.rs` 4 uses, `library.rs` 49, `storage.rs` 15,
`colophon-ffi/src/import_storage.rs` 5, `migration.rs` 1) keep calling the built-ins directly.
They are frozen and are not 0.5.

A boundary test (M1, in `tests/v05_modules.rs`) fails if any file under `src/v05/` or
`src/module/` names `crate::domain::`, `crate::domains::` or one of the four namespace names. Two
exceptions: `module/builtin.rs` and `swift_copy.rs:435`.

### 2.3 Where the four built-ins live

| Option | What moves | What breaks | Verdict |
| --- | --- | --- | --- |
| A. Registry; the four stay in `colophon-core` behind it, under feature `modules-builtin` (default on) | ~600 lines rewired (rows 4–25); no files move | nothing outside the core; checkpoints rebuild once | **0.6** |
| B. The four move to `colophon-modules-luff` now | A, plus ~13,250 lines (`domains/` 12,590, `domain.rs` 367, the import tables) | the legacy 0.3/0.4 surface (73 uses in `library.rs`, `storage.rs`, `engine.rs`, two FFI files) would make a dependency cycle. It must move with them (`colophon-legacy`, ~6,300 lines) or take a registry too. The four `domain_*` tests move | later |
| C. Each module its own crate | B, split four ways | as B | later, if one is reused alone |

**Choose A for 0.6, and move when the legacy surface goes.** This is not caution. The owner's goal
is that the core names no subject and a fifth module needs no core change. A meets both:

- `Registry::with` takes any `Arc<dyn Module>`, so a fifth module can live in its own crate today
  without touching the core.
- After M2, no verdict path calls a module at all (rows 1–3 make the live verdict generic). The
  modules sit behind the security-reviewed code, not inside it.

B would add nothing visible from outside. What it costs is the legacy surface, which the shipped
apps still need until their move.

**What makes the later move mechanical.** After M2, the boundary test proves that only
`module/builtin.rs` and the legacy files name the built-ins. The move then takes four steps:

1. `git mv src/domains` and `module/builtin.rs` into a new crate.
2. Its `register()` fills a `Registry`.
3. `colophon-ffi` and `colophon-wasm` depend on it behind their features.
4. The legacy files go with it, or are deleted.

No wire format or vector changes. Trigger: the legacy 0.3/0.4 FFI is retired.

## 3. The spec

Text changes are in the proposed revision 17 (§11.8 edited, a new §11.9, §20, §21). In summary:

- **What stops being conformance.** 0.3 §6's namespace and kinds table, and every podcast
  specific in 0.3 §5.1 (the namespace, the kind, "episode", deliberate seeks, completion, queue
  edits). They describe the reference implementation's built-in modules.
- **What the protocol defines.** A record, a namespace, a live slot and its generic derivation,
  blobs, imports, and the generic fold conventions that a module MAY adopt. It also defines what a
  replica does with records of a module it lacks.
- **The normative one-entry registry is withdrawn.** The live verdict is generic (§0). The
  freeze design kept a registry so that replicas could not disagree. The generic rule achieves
  that with zero entries, because it reads nothing a module defines. Nothing about podcasts stays
  normative.
- **What a replica without a module does.** It admits, keeps and syncs the module's records,
  judges them by every protocol rule, never refuses one for its kind or payload, and never folds
  it. With a live candidate it does exactly what a replica with the module does: it judges the
  candidate generically, keeps it as the head, superseded or refused by the same rules, and serves
  and retains it. It shows nothing for it.

## 4. Module identity and versioning

### 4.1 Names

- A module `id` follows the namespace grammar (1–128 bytes of `a–z 0–9 . _`). It SHOULD be the
  reverse-DNS name of a domain its maker controls, with `-` written `_`.
- `colophon.` is reserved for the core's own fold.
- A module owns exact namespace names, normally its own `id` and names under it
  (`works.luff.galley.board`, `works.luff.galley.board.comments`).
- The four built-ins are `works.luff.reading.books`, `works.luff.reading.saved`,
  `works.luff.listening.podcasts` and `works.luff.notes`. They own the four grandfathered names.
- The registry refuses two modules with one `id` or one namespace. This is an app's build error,
  never a verdict.

### 4.2 Rules and "update me"

- `rules` only goes up. A released `(kind, v)` keeps its meaning forever. New behaviour is a new
  kind or a new `v`. A bug fix that changes a fold bumps `reducer_schema`, so caches rebuild.
- A module counts, per namespace, the records it skipped because their kind or `v` is unknown to
  it, and the `colophon.module` records naming its `id` with a higher `rules`. Either count makes
  the host show "update this app" **for that module only**. The account never stops for a module.
- **Two devices of one account with different versions.** Both admit everything; both sync
  everything. The newer one shows the new kinds. The older one shows what it understands and says
  "update" for that module. Neither verdict differs (§3).
- **A device without the module.** It shows that the namespace exists and belongs to a module it
  lacks (named by a `colophon.module` record, if there is one). It never says "broken".

### 4.3 How a module is declared in an account

A namespace is declared by F5's `rekey`. That stays the only authority act. Nothing about modules
goes into authority: a `rekey` epoch object with an extra field would stop every 0.5 reader (F1
row 12).

A module MAY also write one record: kind `colophon.module` in its namespace, payload
`{"module": "<id>", "rules": <integer ≥ 1>, "digest": "<64 hex>"?}`.

- **Why now.** A later version that added it would make it an unknown `colophon.` kind, which is
  `newerFormat` for 0.5 readers. Under §11.6 rule 3, a `newerFormat` record by a writer would then
  leave every later proposal in that namespace unresolved for 0.5 readers. Defining it now costs a
  shape check.
- **What it gives.** It says which module a namespace is meant for, which is all a device without
  the module can say. It carries the minimum `rules` for "update me". It holds the `digest` that a
  later module-as-code needs (§7).
- **What it decides.** No verdict. Shape: `module` follows the namespace grammar, `rules` an
  integer of 1 to 2^32−1, `digest` 64 lowercase hex, no other field. A bad shape is
  `invalidPayload` (as for `colophon.accept`). It folds nothing in any module. The core fold keeps
  the highest `rules` per `module` and exposes it in the view.

## 5. Composition: layers that can be used alone

| Layer | Code | Depends on | Usable alone today? | Smallest change to make it yes |
| --- | --- | --- | --- | --- |
| 1 Keyring and authority history | `v05/{encoding,signature,descriptor,ids,slots,vault,members,terms,heads,history}` | nothing above | **Yes in code; no as a package.** History depends only on its own layer (plus `crate::model` for the 0.4 upgrade). An account with zero namespaces is created and verified (`account/create.rs:316`). The FFI has verify-only calls (`account_verify_history`). But it ships only inside the whole `colophon-core` | feature gates (§6); identity-only engine scope (below) |
| 2 Calls and links | `v05/calls.rs`, `replay.rs` | 1 | Yes (the dependency on `engine::paths` is in tests only) | none |
| 3 Pairing and invites | `v05/pairing.rs`, F8's `invite.rs` | 1 | Yes | none |
| 4 Records and namespaces | `v05/records.rs`, `account/derived.rs` | 1 | Yes: a namespace no module owns is admitted and gets an empty fold (`ProjectionState::Unknown`) | M1/M2 make "no module" the normal case, not an `Unknown` arm |
| 5 Blobs | `imports.rs` blob half, `engine/blobs.rs` | 4 | Yes, in any namespace | none |
| 6 Live state | `v05/live.rs`, `engine/live.rs` | 4 | **No:** only podcast positions may be live (verdict and writer) | W2-R (verdict), M1 (writer) |
| 7 Modules | `domain.rs`, `domains/`, `imports.rs` tables | 4–6 | No: hard-wired, a closed enum | M1, M2 |
| 8 Exchange with a home | `engine/exchange.rs`, `engine/paths.rs` | 1, 4 | **No for identity only:** an empty read scope means "every namespace" (`EngineOptions.namespaces`, `engine/mod.rs:64,297`), so a replica cannot ask for authority only | `ReadScope::{All, Only(list)}`, where `Only([])` is authority only; `set_read_scope` the same (M3) |
| 9 The home | `colophon-home-wasm`, `relay/` | 1, 2, 4 (headers only) | **Yes:** names no module, stores headers by stable fields | none; it links the built-ins as dead code until the features exist (M3) |

What an app that wants only identity (Galley's people, companies and agents) links:

| Platform | Today | After M3 |
| --- | --- | --- |
| Rust | `colophon-core` (everything, ~31k lines of domains and legacy included) | `colophon-core` with `default-features = false` (no `modules-builtin`, no `legacy`) |
| Swift | `ColophonFFI` xcframework (all built-ins) + `ColophonKit` + `ColophonSession` | `ColophonFFICore` xcframework (no modules) + `ColophonKit` + `ColophonSession`; no domain kit |
| Kotlin / Android | one AAR with everything | an AAR built from `colophon-ffi --no-default-features --features native05` |
| JS | the `web05` wasm with everything | a `web05` build without `modules-builtin` |

## 6. Packaging per platform

| Platform | How an app takes only the modules it uses | Change |
| --- | --- | --- |
| Rust | Cargo features on `colophon-core` (`modules-builtin`, one per built-in: `module-books`, `module-listening`, `module-saved`, `module-notes`, `legacy`) and the same on `colophon-ffi` and `colophon-wasm`. A fifth module is a crate the app's FFI build registers | M3 |
| Swift | **Already split, confirmed:** `ColophonBooksKit`, `ColophonListeningKit`, `ColophonSavedKit` and `ColophonNotesKit` depend only on `ColophonSession` (`Package.swift`). Leftovers: `reading.saved` in `ColophonSession/NamespaceStore.swift:129` and `SessionTypes.swift:67`; display names hard-coded in `ColophonSessionUI/LibraryPresentation.swift:26-29`. The binary is one xcframework | move the leftovers into `ColophonSavedKit`; read display names from `modules_json`; a second binary target `ColophonFFICore` (M3) |
| Kotlin / Android | The Kotlin SDK is generic. Android leftovers: `NamespaceStore.kt:74`, `SessionTypes.kt:60` (`reading.saved`) | move them into an Android saved helper; two AAR flavours (M3) |
| JS | Generic. One wasm | two wasm builds (M3) |

**Exports stay JSON.** The 0.5 UniFFI and wasm surface already has no domain type: `begin_write
(namespace, kind, payload_json)`, `query_json`, `tools_json`, `begin_import(namespace,
batch_json)`. Keep it. Two additive exports (M2):

- `modules_json()`: the registered manifests.
- In `view_json`, per namespace, `module: {id, rules} | null` and the module's `newer` and
  `invalid` counts.

A module never adds an FFI function. Typed APIs are generated per platform from the manifest's
schemas, as the Swift kits are today (`scripts/generate-swift-domains.py`).

## 7. Modules written outside this repository, later

Two ways, each behind the same seam:

- **Declarative.** A module description that the engine interprets.
- **WASM.** One WASM component per module, run with no host imports, fuel and memory limits and
  NaN canonicalization, under an interpreter on iOS.

**What the 0.5 seam must already be, so that neither needs another core change:**

1. Every crossing is data: payload JSON in, query JSON in and out, state as opaque bytes. No
   callback into the core, and no shared Rust type a component could not produce. (§2.1 is.)
2. A module is named by `id` and `rules` and may be pinned by `digest`. The `colophon.module`
   record carries it, so the code can be found from the account itself. The code could even be a
   blob in that namespace.
3. Nothing a module does is a verdict. A sandboxed module can therefore spoil only its own view,
   and data already written never needs rewriting when the module's form changes.
4. `NamespaceFold` holds `Box<dyn ModuleState>`. A `WasmModule` or `DeclarativeModule` adapter is
   one more implementation of the trait.

**Choice, when it is needed: WASM.** The survey showed that the four real modules do not fit a
description language without escape hatches (saved's search and feeds, listening's playlists and
jobs). A WASM component runs any deterministic fold. An interpreter for a description language can
itself be compiled to a component, so choosing WASM does not rule out the declarative form. The
cost is an interpreter in the engine (wasmi, about 1–2 MB) and slower folds on iOS.

## 8. What "truly standardized" means

A schema enters the standard library (bare names, defined in the spec, with vectors) only if one of
these holds:

1. **The protocol needs it to do its own job.** Examples: blobs, imports, proposals, the module
   record.
2. **Two apps built independently write it and read each other's records.** Each must also have a
   written spec and conformance vectors, and its owner must commit to additive-only change.

**Day one: the `colophon.*` engine kinds only.** These are `importBatch`, `blobPublish`,
`blobReference`, `accept`, `decline`, `resolveHistorical` and `module`, plus `basis`, the generic
live slot, and the blob and import queries. **No subject module is in it.** Each of the four is
one product's schema.

The fold conventions (last writer wins in fold order, `expect` with recorded alternatives, the
`extensions` bag, tombstones) are offered as a helper library for module authors, not as standard:
a module may fold differently.

Candidates later: a three-kind notes core, a saved `capture`, a generic progress record. Each waits
for a second independent app.

## 9. Order of work

| Stream | Owns exactly | Depends on | Runs beside | Vectors | Acceptance (plus the freeze package's common four) |
| --- | --- | --- | --- | --- | --- |
| **W2-R amended** | as the freeze design, plus new `domains/listening/live.rs` and one line of `v05/engine/live.rs` | W1-A | W2-C | §0 table | as the freeze design |
| **M1 Seam** | new `src/module/{mod,registry,core,fold,builtin}.rs`; `src/domain.rs`; `src/imports.rs`; `src/domains/**`; `src/lib.rs`; `src/v05/engine/live.rs`; `src/v05/engine/mod.rs` (only `heads_to_retain`, `begin_import`, the `EngineOptions` registry field); `src/v05/swift_copy.rs`; new `tests/v05_modules.rs` | W2-R merged (it changes `protocol.rs`) | W2-C, W3-H (no shared file) | none | `domain_*` and every `v05_*` test unchanged and passing. A golden test: query outputs of the four over the journey fixtures are identical before and after. A fifth module defined in the test file is registered and folds without editing `src/`. The boundary test (§2.2). `cargo test -p colophon-core --test v05_modules` |
| **M2 Threading and exports** | `v05/account/{read,derived,action,mod,moving}.rs` call sites (rows 8–15); `crates/colophon-ffi/src/v05/api/{engine,session,types}.rs` (`modules_json`, view fields, registry at construction); `surface-names.txt`; generated bindings; `colophon-wasm` registry | M1, and W3-G merged (it owns those files in wave 3) | — | none | as W1-P's SDK commands; checkpoint rebuild once per namespace (`REDUCER_SCHEMA` bump); `modules_json` round trip in Swift, Kotlin and JS |
| **M3 Packaging and identity only** | Cargo features in `colophon-core`, `colophon-ffi`, `colophon-wasm`; `ReadScope` in `v05/engine/mod.rs` and `api/session.rs`; `Package.swift` (`ColophonFFICore`); `scripts/` xcframework and AAR builds; the Swift and Android `reading.saved` leftovers moved to the saved kits; `LibraryPresentation.swift` | M2 | — | none | `cargo build -p colophon-core --no-default-features`; an identity-only journey (create with zero namespaces, sync authority only from a home, verify) on every platform; binary size reported for both artifacts |
| **Spec** | this PR's revision 17 text | — | now | — | review with the freeze text |
| M4 (later) | move the built-ins and the legacy surface out of the core (§2.3) | M3; legacy retired | — | none | boundary test holds with no exceptions |

At most two of these run at once next to the freeze waves: W2-R and M1 never overlap (M1 starts
when W2-R merges, during W2-C or wave 3); M2 waits for W3-G.

**Existing vectors that change: none.** M1–M3 change no verdict. W2-R's live vectors are new.

## 10. Cost, risk, and what not to do now

**Cost.** W2-R gets smaller (one generic function instead of a registry with three outcomes). M1 is
about 600 lines rewired and a new `module/` of about 500, with no file moved. M2 is about 200 lines
in the account and the FFI. M3 is build work. The four built-ins keep their code.

**Risks, plainly.**

- **A live payload check stops being a verdict.** A live `seek` or a payload the podcast module
  rejects becomes the slot head. What is shown falls back to an earlier candidate the replica
  holds, which can differ between replicas (already true, §11.8 "Limit").
- **Fold agreement depends on modules keeping their promise** (a released `(kind, v)` never
  changes meaning). Nothing enforces it but review. Breaking it splits what devices show, never
  what they admit.
- **Checkpoints rebuild once** after M2, on every device. That is local and costs one replay.
- **The M1 shim.** Until M2 lands, `domain::State::new` uses `Registry::builtin()` inside the core,
  so the engine's registry does not reach the account. It is removed in M2 of the same release,
  not left in place.
- **Any kind may be live.** An uncaveated writer can fill live slots in any namespace. It could
  already do so with podcast positions under arbitrary IDs. The per-path and total bounds still
  hold.

**Not now.**

- Moving the built-ins to crates. It waits for the legacy surface (§2.3).
- WASM or declarative modules (§7). Only the seam that admits them is built now.
- A module declaration inside authority (a `rekey` field or a new entry kind).
- Module-defined verdicts of any kind.
- Promoting any subject module to the standard library.

## Decisions for the owner

| Decision | Default |
| --- | --- |
| In 0.6, replace the one-entry live registry with the generic rule, keeping the podcast `seek` refusal frozen (§A) | yes |
| Define `colophon.module` in 0.5 (a shape check only) to spare 0.5 readers "update me" on proposals later | owner's call; no by default (0.5 takes nothing from this note) |
| Built-ins stay in the core in 0.6 behind the registry, move when the legacy surface goes | yes |
| Built-in module IDs under `works.luff.` | yes |
| Ship a second, module-free binary per platform (`ColophonFFICore`, a slim AAR and wasm) | yes, in M3 |
| Third-party modules as a goal, with WASM when the first one arrives | yes, not before an outside app asks |
