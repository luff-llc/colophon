# Domain specifications handoff

2026-11-06 · `domains` worktree · files left uncommitted.

Start with [the domain index and shared contract](domains/README.md). This work documents
the Swift 0.1 behavior and proposes the domain contracts needed beyond the Rust 0.2 preview.
It does not implement reducers or certify migration parity.

## Coverage

Read `docs/app-migration.md`, including Domains and Moving existing libraries, and
`spec/colophon-0.2.md` before tracing the source. The read-only Marginalia baseline was
`3503057517a0e14e2f21325403fa1bc3a23e487c`, confirmed unchanged at completion. Source discovery
used `git ls-tree`; source contents came from `git show HEAD:<path>`. No Marginalia working-tree
files or personal library contents were used or copied.

| Domain | Coverage | Confidence and remaining uncertainty |
| --- | --- | --- |
| [reading.books](domains/reading.books.md) | All 9 old kinds; Shelf screens/intents, legacy Apple and Android boundaries; 10 proposed kinds and 8 queries | High for the small fold and current Shelf call paths. Import still needs executable cases for orphan notes, ID reuse, string-only alternatives and malformed historical values. |
| [listening.podcasts](domains/listening.podcasts.md) | All 29 advertised kinds plus 4 service-only kinds; Taupe player, transcripts, notes, playlists, widgets, controls, intents, watch/CarPlay, shared access and legacy publishers; 30 proposed kinds and 17 queries | Medium-high for operation inventory and static hot paths. Service authorization, retained-source verification, legacy publication receipts and historical agent jobs need integration vectors. Tick frequencies are source observations, not measured core costs. |
| [reading.saved](domains/reading.saved.md) | All 36 old kinds, including restore families; Later reader, Safari/share/widget/intent paths, feeds, annotations, review, answers and subscriptions; 24 proposed kinds and 19 queries | Medium for migration parity: the largest nested validation and recovery surface. Atomic snapshot replacement, deleted-source closure, historical branches and custody need executable importer proofs. |
| [notes](domains/notes.md) | All 12 old kinds, including cell.output omitted from tool specs; Scribenda notebooks/cells, materials, proposals, intents and podcast continuation; 13 proposed kinds and 10 queries | High for fold inventory and ordinary app paths; medium for importing exact proposal inputs and kept reviews after reference rewriting. Large cell sources remain an explicit design limit. |

[Saved-reading nested models](domains/reading.saved-models.md) supplements its operation table
with source, archive, annotation, review and answer-custody shapes. Every domain separates
actual old validation/folds from the proposed behavior and from open questions. Tables include
write/read call paths, static heat, derived versus retained data, conflicts, device-local state,+blob ownership and an explicit disposition for every old kind.

The total inventory is **90 old kinds**, with **77 proposed kinds** and **54 named domain
queries**. Common import-evidence and host blob-index APIs are additional. The index gives
per-domain reducer/index estimates; these exclude importer codecs, crypto, host I/O, FFI and
tests. No conformance payloads were added.

## Decisions to carry into implementation

- Preserve verified source history and provenance, including old operation ID, author label,
  exact signed-body digest, outcome and output mapping. The new importer signs its own effects;
  historical authors and roles remain labelled claims.
- Use clean commands for effective changes, with component revision maps. Keep stale, invalid,
  unknown and otherwise unprojectable history in durable encrypted import evidence. Do not
  make a rejected old write effective by dropping its expectation.
- Keep reducer ordering deterministic, add permanent occurrence tombstones and complete
  attributed conflicts, and preserve unknown fields through extensions. These deliberately
  improve several old folds; they are not byte-for-byte replay compatibility.
- Serve indexed pages, individual records and counts. UI renders, scroll frames and playback
  ticks use loaded values; widgets consume local snapshots. Whole-state copies are background
  export only.
- Treat retained originals, transcripts and custody as blobs; downloads, availability, browser
  presence, engine state, selection, credentials and transient drafts remain device-local.

## Gaps and coordination required

1. Agree the proposed Blob descriptor, encrypted storage/access contract, import-evidence
   sidecar and SDK historical-conflict overlay with the core/FFI workers. These are required
   migration infrastructure, not facilities already guaranteed by 0.2 §7.
2. Resolve compatibility with already-written 0.2 preview data: especially notes addNote/editNote
   versus cells, and saved-reading capture's required URL versus source-only/native content.
   The documents propose behavior without editing the core specification or crates.
3. Implement and test publication barriers for decomposed old atomic restores. Reference maps
   must preserve lifecycle identity, DAG parents, source custody, component heads and accepted
   historical outcomes. Catch-up must be idempotent and must not overwrite native 0.2 changes.
4. Build synthetic vectors for every kind and its invalid/stale/duplicate cases, large graphs,
   unknown fields, missing blobs, checkpoint invalidation and reverse delivery. Reading needs
   coverage across content snapshot versions 1–7 and annotation versions 1–5. Historical
   jobs must remain inactive; imported acceptance must never manufacture current agent authority.
5. Benchmark representative 100k-operation libraries and the actual UI query paths. Static
   heat labels and estimated Rust LOC are planning inputs; no performance claims were measured.
6. Legacy Apple and Android journals, external Booklist exports and the separate source.native
   namespace need their own source-format/namespace adapters. Their app boundaries are called
   out here; they must not be mistaken for extra kinds within these four 0.1 namespaces.
7. Product choices remain explicitly listed per domain, notably subscription conflict display,
   review enablement, browser selection, large cell sources and copy-return behavior.

No real library was inspected, so this inventory cannot establish which historical payloads
occur in a user's data or prove successful import of that data. Unsupported or unverifiable
records and missing required blobs must remain visible migration gaps with the original archive
retained; a projection that merely looks complete is insufficient.

## Verification and workspace state

Checked all four every-kind mapping tables against their inventory counts: 9 / 33 / 36 / 12,
with no duplicate mapping rows. Checked proposed command and query counts against the index,
cited Swift/Kotlin filenames against the committed source tree, local Markdown links, table
column consistency and trailing whitespace. These are documentation checks, not execution of
Swift validators, Rust tests or a migration rehearsal.

Only `docs/domains/` and this explicitly requested handoff were written. No crates, source
repository files, Git metadata or build outputs were changed by this work. No builds were run
and no cleanup was needed. All deliverables remain uncommitted. Work stops with this handoff.
