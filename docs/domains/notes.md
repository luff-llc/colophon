# notes

Proposed 0.3 port; [shared conventions](README.md) apply. Source prefix `N` is
`packages/Colophon/Sources/ColophonNotes/`; `M` is `apps/suite/Margins/` (the Scribenda app).
The actual domain is notebooks, cells and entries; the 0.3 preview's addNote/editNote model
does not represent that hierarchy.

## 0.1 operations, validation and conflicts

Sources: `N/Notes.swift`, `Notes+Spec.swift`, `Notes+Entries.swift`, `Notebooks.swift`,
`NotesContentValidation.swift`. Every admitted operation is checked for v=1 and a valid
notebook ID. IDs in content validation are nonempty, ≤512 UTF-8 bytes, no newline or NUL.
Other control characters are not all excluded. Optional strings accept absent/null. Invalid
content operations and cross-notebook cell operations enter `invalidOperations`.

| Kind | Payload | Actual fold |
| --- | --- | --- |
| `notebook.create` | `notebook:ID,title:Text,kind:Text?=notebook,topic:Text?` | First ID wins; writer enum notebook/lecture/seminar/document, fold accepts any kind string. Creates empty order and timestamps. |
| `notebook.rename` | `notebook:ID,title:Text` | Existing notebook, ordered title replacement, no CAS. |
| `notebook.archive` | `notebook:ID,archived:Bool?=true` | Reversible flag; archive does not prevent cell edits. |
| `cell.put` | `cell:ID,notebook:ID,kind:markdown\|latex\|code\|raw,source:Text; language:Text?,after:ID?,expect:Rev?,entry:ID?` | Create after existing anchor, otherwise top. Edit compares non-null expect; stale text appended to alternatives. Success changes source/kind, language only when string supplied, entry only when string supplied, revision and editor. `after` ignored for edit. Entry must belong to notebook. Deleted ID never resurrects: source plus contextual late edit retained. |
| `cell.resolve` | `cell:ID,notebook:ID,source:Text,expect:Rev?` | Existing cell; stale source becomes alternative; success sets source/revision/editor and clears alternatives. Doesn't change kind/language. |
| `cell.move` | `cell:ID,notebook:ID,after:ID?` | Remove from notebook order, insert after extant anchor or top. Self-anchor becomes missing after removal, hence top. No CAS. |
| `cell.delete` | `cell:ID,notebook:ID` | Removes cell/order, records permanent deleted ID and notebook ownership even for an absent cell. |
| `cell.output` | `cell:ID,notebook:ID,sourceDigest:Text,runtime:Text?,outputs:[{mime:Text,data:Text}]?,error:Text?` | Existing cell and string digest; latest run wins. Invalid output elements skipped; missing runtime empty; no hash syntax check. No execution. This kind is in kinds and builder but **omitted from operations/tool specs**. |
| `entry.put` | `entry:ID,notebook:ID,title:Text?,date:Day?,tags:Text[]?,expect:Rev?` | Create requires no expect; existing entry requires exact revision even when expect omitted. Stale edit retains complete title/date/tags/revision/author alternative. Successful edit retains old alternatives. Entry cannot cross notebooks. |
| `attachment.add` | `attachment:ID,notebook:ID,entry:ID?,role:reading\|slides\|handout\|image\|audio\|file\|link,name:Text,mime:Text?,blob:BlobRef?,source:SourceReference?` | Exactly one of blob/source. Immutable ID; exact same payload and signer retries accepted, other reuse invalid. Entry, if present, must exist in notebook. |
| `entry.propose` | `proposal:ID,notebook:ID,entry:ID,title:Text?,tags:Text[]?,markdown:Text,inputs:{cellID:Rev}` | Immutable proposal. Requires exact map of every current entry cell revision and no cell alternatives. Same payload/signer retry only. Does not replace cells. |
| `proposal.review` | `proposal:ID,notebook:ID,keep:Bool,markdown:Text?` | App/device (not agent/service); pending only; keep requires inputs still current. Sets kept/dismissed and review attribution; optional edited markdown stored separately. Matching terminal retry by same reviewer is accepted; conflicting review invalid. |

Additional content bounds: title ≤512 bytes, valid Gregorian date, ≤64 unique nonempty tags
each ≤128 bytes; optional expectation ≤512 bytes. Attachment name follows ID bounds, MIME
≤256 bytes; old `BlobRef={digest,plain:Digest,epoch:Int,size:Int}`, epoch>0, size 0…512 MiB,
lowercase SHA-256 digests. Proposal markdown/review markdown ≤16 KiB, input map ≤2,048 IDs.
Cell source size is not bounded by these old content validators.

`SourceReference` (`N/NotesAttachment.swift`) is either `{kind:web,url:Text}` (HTTP(S), host,
no credentials, ≤4,096 bytes; library-location fields absent/null) or
`{kind:library,library:ID,namespace:ID,artifact:ID,revision:Rev,quote:Text?,page:Int?,
seconds:Number?,recording:Digest?}`. Quote ≤16 KiB, page≥0; seconds finite ≥0 requires a
recording digest. Source pointers are descriptive until resolved under source read access.

Notebooks increment an internal applied counter before checking target existence. Existing
notebook touched/updated is changed even by some ignored/unknown or malformed cell kinds;
updated uses max claimed date. Cell text alternatives are strings; original operation history
has full attribution. Unknown extras are retained in the log, generally not the projection.
Unknown kinds with a valid notebook can touch it even though they mutate no content. These
quirks are not proposed for new 0.3 operations.

Derived: active notebooks by touched, notebook order→cells, entry/attachment/proposal indexes,
proposal input currency and `outputIsCurrent = SHA256(UTF8(source)) == lastRun.sourceDigest`.
`N/NotesEntry.swift`, `NotesOrganisationProposal.swift` define complete metadata alternatives
and pending/kept/dismissed status. Output validity is a source match, not proof code ran safely
or produced the claimed output. No kernel state is replicated.

## Usage inventory and heat

| Surface / paths | Writes | Reads and heat |
| --- | --- | --- |
| `M/MarginsHome.swift`, `NotebookForm.swift`, `NotebookSidebar.swift`, `NotebookWorkspace.swift` | notebook create/rename/archive; entry.put and initial cell.put | Notebooks/entries/order on namespace revision, cached values per render/scroll. Loose-note quick capture creates notebook/entry/cell as needed. |
| `M/CellDrafts.swift`, `NotebookDocument.swift`, `CellView.swift`, `CellTextView.swift` | cell.put on draft commit, cell.move/delete/resolve | Cell source/revision, order, alternatives. Text editor keystrokes and selection are local; saving is an action/debounce boundary. Never refold per keystroke. |
| `M/NotebookDocument.swift`, `JavaScriptRunner.swift` | cell.output after execution | Cell source and output; render each visible cell, execution on user action. |
| `M/LateEditsSection.swift` | cell.put with a new ID to recover a deleted cell | Late edits/parent order on render and recovery action. |
| `M/NotebookEntryDetails.swift` | entry.put | Entry metadata and post-write revision check on action. |
| `M/NotebookMaterialImport.swift`, `NotebookMaterialLink.swift`, `NotebookMaterialStorage.swift`, `ScribendaInkCaptureSheet.swift` | attachment.add; sealed file/ink blobs | Entry materials on render; file decode/write on import/open, not scroll. |
| `M/NotebookProposalReview.swift`, `NotebookProposalEdit.swift` | proposal.review | Proposals and current input revisions on review. entry.propose is exposed through the typed module/tool path; no native app producer was found in these views. |
| `M/MarginsIntents.swift` | notebook.create + cell.put, or append cell.put | Notebook entity suggestions and last cell on cold intent execution. |
| `N/PodcastNoteContinuation.swift`; `apps/suite/Shared/Transcripts/SharedTranscriptAccess.swift`, `SharedTranscriptReader.swift` | Continuation creates notes hierarchy/material pointer through Notes commands | Exact podcast note/transcript references; detail/action path, requires listening access separately. |
| Legacy `apps/apple/App/Notes/AppModel+Notes.swift`; Android `android/app/src/main/kotlin/xyz/marginalia/android/notes/NotesScreen.kt`, `AppModel.kt`, `store/NotebookDocumentImport.kt` | Older journal notebook/page/annotation/import mutations | Legacy notebook documents and material projections, per screen/action. Not direct cell.* Colophon writes. |

No committed Scribenda widget/share-extension writer was identified. `MarginsApp.swift`
requests both notes and podcast namespaces for continuation. A denied source namespace must
not hide the notebook itself or automatically widen its grant.

## Proposed 0.3 design

Thirteen kinds, v=1. IDs, blobs, extensions and attribution use README. Existing preview
`createNotebook` remains; preview `addNote`/`editNote` should become SDK conveniences for a
single markdown cell, with explicit notebook identity. They must not be treated as historical
0.1 kinds. Coordinate any wire compatibility requirement before changing the implemented preview.

| Kind | Payload | Reducer semantics |
| --- | --- | --- |
| `createNotebook` | `id,title; kind:enum=notebook,topic:Text?` | First creation wins; initial active empty notebook. |
| `renameNotebook` | `id,title; expect:Rev?` | Metadata CAS. |
| `archiveNotebook` | `id,archived:Bool; expect:Rev?` | Metadata CAS; reversible, content survives. |
| `putCell` | `id,notebook,kind:enum,source:Text; language:Text?,entry:ID?,after:ID?,expect:Rev?` | Create if absent; edit text component otherwise, never move notebook. Optional language/entry omitted preserves, null clears. Entry must exist. After only controls creation. Retain full stale versions. |
| `resolveCell` | `id,notebook,source,expect:Rev,resolves:Rev[]` | Set source only after exact head and alternative-set check. |
| `moveCell` | `id,notebook,after:ID?; expect:Rev?` | Compare notebook order head; remove then insert. Missing anchor deterministically places at top; reject self-anchor. |
| `deleteCell` | `id,notebook; expect:Rev?` | Compare cell text head; tombstone, retain outputs/alternatives/late edits. |
| `recordOutput` | `id:ID,cell,notebook,sourceDigest:Digest,runtime:Text,outputs:[{mime:Text,text:Text?,blob:Blob?}],error:Text?` | Immutable run record; exactly one text/blob per output. Latest run is derived; stale output never edits source. |
| `putEntry` | `id,notebook; title:Text?,date:Day?,tags:Text[]=[],expect:Rev?` | Complete metadata value; create expects absent, existing edit requires explicit current head; stale complete alternatives retained. |
| `resolveEntry` | `id,notebook,title:Text?,date:Day?,tags:Text[],expect:Rev,resolves:Rev[]` | Explicitly settle metadata alternatives; new capability absent from 0.1. |
| `addAttachment` | `id,notebook,role,name; entry:ID?,mime:Text?,blob:Blob?,source:SourceReference?` | Exactly one blob/pointer; immutable descriptor and ownership; identical logical retry only. |
| `proposeEntry` | `id,notebook,entry,markdown,inputs:{ID:Rev}; title:Text?,tags:Text[]=[]` | Exact current entry cell set with no conflicts. Proposal remains separate and becomes stale when inputs change. |
| `reviewProposal` | `id,notebook,keep:Bool; markdown:Text?,expect:Rev?` | App/device only; pending→kept/dismissed, keep requires current inputs. Does not overwrite originals or execute code. |

Retain 0.1 entry/material/proposal bounds. New inline cell sources and runs are limited to
256 KiB per source/run, ≤100 output descriptors; larger imported output data becomes blobs.
SourceReference keeps the old two variants but pins new library/revision IDs through the
import map. Unicode boundary checks apply to quoted source resolution, not arbitrary text edits.
Every mutation validates fully before changing indexes. Only an effective content/order change
touches the notebook. Notebook, cell, entry, order and proposal heads are separate. New
conflicts retain full source, kind, language, entry and attribution. Cell content IDs are
namespace-global with immutable notebook ownership; membership changes stay within notebook.

Maintain notebook order as indexed sequence (not a full array copied for every query), entries
by notebook/touched, cells by entry, materials/proposals by parent and current-source hashes.
Kernel processes, output rendering, file availability, handwriting editing, cursor selection,
drafts and view state stay device-local. Immutable ink/file bytes are retained blobs. Cross-app
attachments require explicit source access; do not duplicate source permissions into notes.

| Query(arguments) | Result value | UI path |
| --- | --- | --- |
| `notebooks(archived:Bool=false,search?:Text,cursor?,limit?)` | Page `{id,title,kind,topic?,touched,entryCount,cellCount,revision,created,updated}` | Sidebar/intent picker, touched descending then ID. |
| `notebook(id)` | `{id,title,kind,topic?,archived,revision,orderRevision,entryCount,cellCount,materialCount,extensions}` | Workspace header. |
| `entries(notebook,cursor?,limit?)` | Page `{id,title?,date?,tags,touched,revision,created,updated,cellCount,alternativeCount}` | Entry list; touched descending then ID. |
| `entry(notebook,id)` | `{id,current:{title?,date?,tags,revision,author,authorLabel},cellCount,attachmentCount,proposalCount,alternativeCount}` | Entry detail, no embedded collections. |
| `cells(notebook,entry?:ID,cursor?,limit?=30)` | Page `{id,kind,language?,entry?,sourcePreview,revision,alternativeCount,outputIsCurrent,latestRun?}` | Virtual document/editor; notebook sequence order. Omitted entry=all; null=unassigned. |
| `cell(notebook,id)` | `{cell:Attributed,kind,source,language?,entry?,outputIsCurrent,latestRun?,extensions}` | One editor or execution input. |
| `attachments(notebook,entry?:ID,cursor?,limit?)` | Page `{id,role,name,mime?,blob?,source?,revision,authorLabel}` | Materials panel, ID order; byte availability resolved locally. |
| `proposals(notebook,entry,status?:pending\|kept\|dismissed,cursor?,limit?=20)` | Page `{id,title?,markdownPreview,revision,status,inputCurrent,reviewRevision?,authorLabel}` | Review rows; full immutable proposal retrieved via conflicts/detail selector below. |
| `contentDetail(notebook,category:run\|proposal\|cellConflict\|entryConflict\|lateEdit,id,cursor?,limit?=20)` | `{record:JSON?,versions:Page<AttributedCandidate>}` with category-specific run `{cell,sourceDigest,runtime,outputs,error?}` or proposal `{entry,markdown,inputs,title?,tags,reviewedMarkdown?}` | Explicit full run/proposal or paged alternatives; 1 MiB cap. |
| `noteCounts(notebook?:ID)` | `{notebooks,archived,entries,cells,materials,pendingProposals,conflicts,lateEdits}` | Badges and empty states; maintained counters. |

## Every-kind import mapping

The README manifest records every old operation ID, author label and signed-body digest.
No old code is run during import. Preserve the original signed output as an assertion.

| 0.1 kind | Clean mapping |
| --- | --- |
| `notebook.create` | `createNotebook`; preserve kind/topic; unsupported kind goes to evidence with a visible migration gap, not a renamed notebook type. |
| `notebook.rename` | `renameNotebook` for applied title, conditional against imported metadata head. |
| `notebook.archive` | `archiveNotebook`, making old default true explicit. |
| `cell.put` | `putCell`; resolve old default/omitted semantics against source state (especially language and entry). Map after/parent IDs. Applied edits translate text heads; stale and deleted-cell attempts become full historical alternatives. |
| `cell.resolve` | `resolveCell` with the mapped current head and actual imported alternatives; preserve formerly stale resolution in evidence. |
| `cell.move` | `moveCell`, translate missing/self old anchor to explicit top, recording original anchor in evidence; retain old sequential order. |
| `cell.delete` | `deleteCell`, including ownership/tombstone when no visible cell existed. Late source edits remain evidence and recover-as-new candidates. |
| `cell.output` | `recordOutput`; old data strings become inline text or content-addressed blob with original MIME. Malformed skipped elements stay evidence; invalid sourceDigest cannot be certified current. Keep historical runs even though 0.1 shows only lastRun. |
| `entry.put` | `putEntry`; map cell/entry revision references independently, keep complete stale alternatives and historical authorship. Do not resolve old alternatives implicitly. |
| `attachment.add` | `addAttachment`; re-seal accessible blob or remap pointer; retain unavailable reference distinctly. Same-ID/different-body attempts remain invalid evidence. |
| `entry.propose` | `proposeEntry` only for originally accepted proposals with mapped exact input set; historical invalid proposals stay evidence. Preserve original markdown/title/tags and signer claim. |
| `proposal.review` | `reviewProposal` for original accepted result, preserving old reviewer as provenance. Importer app signs the import; no agent can self-accept. If translated inputs cannot reproduce a historical keep, preserve the kept historical contribution as evidence pending repair rather than claim a fresh acceptance. |

Preview addNote/editNote records are 0.3 data, not inputs for the 0.1 translator. Old journal
notebook documents from Apple/Android need a separate source-format adapter. Cell output bytes,
attachments, notebook content and alternatives are not disposable caches. Drop only kernels,
editor drafts, selection, rendered HTML and derived currency/count/index caches. Unreadable
attachments remain missing; they must not be replaced with empty files.

## Open questions

- Decide how already-written 0.3 preview addNote/editNote libraries coexist with cell kinds;
  this spec does not change the wire evaluator.
- Large cell source support beyond 256 KiB needs either a source-blob editor contract or a
  deliberate increased limit. Import must report the limit rather than truncate source.
- Confirm attachment removal and notebook hard deletion as future features; 0.1 has neither.
- Exact nested source-pointer rewriting and preserved kept proposals need synthetic import
  vectors. Static call-path review is high confidence; runtime performance remains unmeasured.

## Wall-clock dates

Notebooks, entries and cells carry `created` (claimed date of the first effective write) and
`updated` (claimed date of the latest effective write) beside the logical `clock`/`touched` order.
They are the signers' claimed operation dates (§5 metadata): display values, never ordering or
authority. Entry `current` and cell/notebook details include them; content comparisons ignore them.
