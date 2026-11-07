# reading.books

Proposed 0.3 port; baseline and conventions are in [README](README.md). Source prefix `B` is
`packages/Colophon/Sources/ColophonBooks/`; `S` is `apps/suite/Shelf/` in Marginalia.

## 0.1 operations and projection

Sources: `B/Books.swift`, `B/Books+Spec.swift`, `B/Bookshelf.swift`.
`Books.operations` validates required types and enumerated statuses for generated writers.
`Bookshelf.apply` independently performs the weaker checks below; it does not test `v`.
Malformed or unknown operations usually disappear from the projection, but remain in the
admitted operation log. The only domain-level conflict ID list is for stale plans.

| Kind | Payload (required by writer; `?` optional) | Actual fold and conflict behavior |
| --- | --- | --- |
| `book.add` | `book:ID,title:Text,author:Text,isbn:Text?`; extra `pages:Int?`, arbitrary JSON | First existing ID wins. Fold requires only book and title; author defaults empty. Creates unplanned reading, fraction 0, operation date and `sequence=books.count`. Stores extras except book/title/author/isbn. `pages` is both read and retained in extras. |
| `book.edit` | `book:ID,title:Text?,author:Text?,pages:Int?`, extras | Existing book only. Patch typed title/author/pages; merge extra keys except book/title/author/isbn/pages. `isbn` is ignored. **Does not advance revision**. No CAS, including an extra `expect`. No positivity check on pages. |
| `book.remove` | `book:ID` | Removes book and all notes with that book ID. No tombstone; a later add with the same ID recreates it. |
| `book.setPlan` | `book:ID,status:Text,started:Text?,finished:Text?,reread:Bool?,expect:Rev?` | Existing book; any string status accepted by fold. Non-null stale expect appends operation ID to conflicts. Otherwise replaces current reading, or appends if reread=true; absent dates become nil; advances plan/book revision. Dates are not validated by fold. |
| `book.progress` | `book:ID,fraction:Number,page:Int?` | Existing book; newest report wins even backwards. Page becomes nil if absent; missing fraction retains current value. Builder clamps fraction to [0,1], fold does not. Does not advance book revision. |
| `note.add` | `note:ID,book:ID,text:Text,quote:Text?,location:Text?` | First note ID wins. Does **not** require an existing book. Stores author label, created date, sequence=notes.count and revision. |
| `note.edit` | `note:ID,text:Text,expect:Rev?` | Existing note. Stale string expect appends text to alternatives; otherwise replaces text/revision. Existing alternatives remain. No quote/location editing. |
| `note.resolve` | `note:ID,text:Text,expect:Rev?` | Same stale behavior; successful resolution replaces text/revision and clears every alternative. |
| `note.delete` | `note:ID` | Removes note without tombstone; later note.add can reuse ID. |

The writer's statuses are `unplanned|wantToRead|reading|paused|finished|doneEnough|abandoned`.
Book dates are calendar declarations. Source `Bookshelf.sorted` orders by descending insertion
sequence, not last edit; note query sorts `(sequence,id)` ascending. Sequence uses collection
count, so removals can produce ties; the old book sort has no tie-breaker. Alternatives contain
only text, not full author/revision context, although that context remains in the log.

Derived in `S/BookSummary.swift`: finished/status grouping, percent, page-count estimate from
page/fraction when fraction > .02, spoken labels. `S/ShelfModel.swift` builds status sections,
finished-year groups, notesByBook and Open Library/ISBN membership once per library revision.
Do not persist these projections. Book metadata extras in use are `coverID:Int`, `year:Int`,
`openLibraryKey:Text`, `pages:Int` and `copyLoan:Object`.

`B/BookCopyLoan.swift` defines copyLoan `{version:1,status:needsReturn|returned,
requestID:Text?,reflection:Text?,provenance:{producerID,acceptingUserID,confirmedByUser:Bool,
sourceQuote:Text?,sourceContext:Text?}?}`. A returned value requires a nonempty request ID and
confirmed provenance in this typed decoder. `B/BookIntentCommands.swift` constructs ordinary
`book.edit`/`book.setPlan` writes: return retries compare the entire accepted event; a fresh
loan read is required because the fold has no CAS. `intent` on a plan remains log-only;
copyLoan is extra JSON, not independently adjudicated human approval by the fold.
`B/BooklistRecordAdapter.swift` keeps raw Booklist JSON and namespaced IDs; its status mappings
are Wish List→wantToRead, Reading→reading, Read in YYYY→finished/year. It defines no additional
Colophon operation kind and cannot invent exact finish dates from a year.

## App usage and heat

| Surface and source paths | Writes | Reads / heat |
| --- | --- | --- |
| Shelf `S/ShelfModel.swift`, `S/ShelfModel+Plans.swift`, `S/BooksInteractionController.swift` | add, edit, remove, setPlan, progress; intent helper uses edit for return | Full Bookshelf once per revision and after a write; book lookup and cached sections per render. User actions, not scroll writes. |
| `S/ShelfHome.swift`, `S/BookSummary.swift` | Through model | Status sections and year groups per render/list scroll; summaries are plain values. Membership set during search. |
| `S/ProgressSheet.swift`, `S/NoteEditorSheet.swift`, `S/BookNotesSection.swift` | progress; note.add/edit/delete/resolve | Single book, notes and alternatives on presentation/render and save. Draft typing is local until save. |
| `S/ShelfIntents.swift` | edit pages, progress, note.add | Entity lookup reads shelf on intent execution; bounded entity suggestions/search needed. Cold launch background action. |
| Legacy `apps/apple/App/Library/BookTrackingView.swift`, `BookPage.swift`, `Books/BookActions.swift`, `Books/BookJournal.swift`, `BookTableView.swift` | Older Marginalia journal book mutations, not these nine opcodes | Legacy book/reading/note projections on screen and action. Port adapter required. |
| Android `android/app/src/main/kotlin/xyz/marginalia/android/AppModel.kt`, `books/BookTrackingScreen.kt`; `android/core-journal/src/main/kotlin/xyz/marginalia/journal/BookReading.kt` | Legacy author book/plan/progress mutations | Compose book lists/detail; writes on action. No direct ColophonBooks implementation. |

No committed Shelf share extension or widget writer was found. Shared suite lifecycle in
`apps/suite/Shared/SuiteLibrary.swift` and `SuiteLaunch.swift` manages sessions, not book kinds.
Legacy/Android paths do not prove signed 0.1 library compatibility; their journal import is a
separate adapter. No reading timer or per-frame book write was identified in Shelf.

## Proposed 0.3 design

Ten clean kinds, all `v:1`. Apply the shared extension, attribution, invalid and tombstone rules.
Text title must be nonblank, ≤16 KiB; creator ≤4 KiB; note text ≤256 KiB; quotes ≤256 KiB and
locations ≤4 KiB. Days are validated; pages >0, page ≥0, fraction in [0,1]. Unknown historical
status strings stay evidence, not silently coerced to unplanned. ISBN is descriptive, not identity.

| Kind | Payload | Reducer |
| --- | --- | --- |
| `addBook` | `id,title,creator:Text; isbn:Text?,pages:Int?,coverID:Int?,publicationYear:Int?,catalogKey:Text?` | Create once, unplanned initial reading, immutable added order. Duplicate ID conflicts unless exact logical retry. |
| `editBook` | `id; title,creator,isbn,catalogKey:Text?; pages,coverID,publicationYear:Int?; expect:Rev?` | Patch metadata against metadata head; explicit null clears nullable fields. |
| `deleteBook` | `id; expect:Rev?` | Tombstone book and hide children, compare activity head. |
| `setPlan` | `id,status; started:Day?,finished:Day?,reread:Bool=false,expect:Rev?` | Compare plan head; replace current reading or append reading with ID=operation ID. Omitted dates preserve, explicit null clears (intentional improvement over 0.1). Reread starts with null dates. |
| `position` | `id,fraction:Number; page:Int?` | Ordered report, may move backwards, updates progress head only; omitted page preserves, null clears. No invented reading session. |
| `addNote` | `id,book:ID,text; quote:Text?,location:Text?` | Requires live parent; immutable parent and creation order. |
| `editNote` | `id,text; expect:Rev?` | Text CAS, complete attributed stale alternatives. |
| `resolveNote` | `id,text,expect:Rev,resolves:Rev[]` | Exact observed head and alternatives; clear only the reviewed set. |
| `deleteNote` | `id; expect:Rev?` | Permanent note tombstone. |
| `setCopyLoan` | `id,status:needsReturn\|returned,requestID:ID; reflection:Text?,proposal:JSON?,expect:Rev?` | App/device only; compare loan head; signer-scoped request receipt. Returned is the signer's confirmed action, not a payload claim of another person's signature. |

Keep object activity, metadata, plan, progress and loan heads separately. Book edits must not
invalidate a plan expectation. Any effective child mutation advances parent activity. Preserve
every reading, not merely current status. Images are URLs/catalog references or blobs; decoded
covers and lookup responses are local caches. Timers, search text, scroll, sheets, drafts and
pending accepted-intent outboxes stay local.

Query shapes (`Attributed` adds the README authenticated fields):

| Query(arguments) | Result value | Consumer / index |
| --- | --- | --- |
| `books(status?:Text, finishedYear?:Int, search?:Text, cursor?, limit?)` | Page of `{id,title,creator,isbn?,coverID?,status,page?,pages?,fraction,started?,finished?,noteCount,conflictCount,revision}` | Shelf sections/search, indexed status/year/title; insertion descending, ID tie-break. `finishedYear:null` selects undated when explicitly supplied. |
| `book(id)` | `{book:Attributed, heads:{metadata,plan,progress,loan,activity},currentReading,loan?,extensions}` | Detail/save, no embedded notes/history. |
| `bookCounts()` | `{total,byStatus:{Text:Int},finishedYears:[{year:Int?,count:Int}],conflicts:Int}` | Sidebar/year headings, maintained counts. |
| `bookNotes(book,cursor?,limit?,order:oldest\|newest=newest)` | Page of `{id,textPreview,quotePreview?,location?,revision,alternativeCount,authorLabel}` | Notes rows, parent/order index. |
| `note(id)` | `{note:Attributed,text,quote?,location?,book,alternativeCount,extensions}` | Editor; no full alternatives array. |
| `readings(book,cursor?,limit?)` | Page of `{id,status,started?,finished?,revision}` | Reread history, newest first. |
| `catalogMembership(keys:Text[≤100])` | `[{key,bookIDs:ID[≤100],total:Int}]` | Search result batch; no whole ownedKeys transfer. |
| `conflicts(object:ID,cursor?,limit?)` | Page of `{operation,component,expected?,found?,candidate:JSON,author,authorLabel,clock,historical:Bool}` | Conflict/late-edit review. |

## Every-kind import mapping

All rows use the README provenance/evidence contract. Preserve add extras including unknown
Booklist raw values; do not publish raw records in conformance fixtures.

| 0.1 kind | Clean operations / treatment |
| --- | --- |
| `book.add` | `addBook`, mapping book→id, author→creator, year→publicationYear, openLibraryKey→catalogKey. Seed plan unplanned. Re-add after remove gets a new lifecycle ID; duplicate ineffective adds go to evidence. |
| `book.edit` | `editBook` for actual changed fields; translate recognized copyLoan to `setCopyLoan` only if its typed validation passed. Preserve unrecognized loan JSON in extensions/evidence. Never import ignored isbn as an edit. |
| `book.remove` | `deleteBook` with imported activity head; retain removed book and notes in history. Map later old recreation separately. |
| `book.setPlan` | `setPlan` with dates explicitly null when old fold cleared them, translated plan head and reread. Stale plans remain evidence alternatives. Retain ignored intent as historical provenance. |
| `book.progress` | `position`, explicitly null page if absent in old payload. Out-of-range fraction/page cannot pass new validation: retain report in evidence with diagnostic; no silent clamp. |
| `note.add` | `addNote` with mapped parent and note lifecycle ID. Orphan notes remain pending evidence until a matching source parent is available; never invent a book. |
| `note.edit` | `editNote` for applied text; recover full attribution of stale alternatives from original operation, not the old string-only array. |
| `note.resolve` | `resolveNote` with translated current head and exact imported alternative set; a formerly stale resolution remains evidence. |
| `note.delete` | `deleteNote`; a later reused note ID is a separate occurrence. |

Drop only derived sections, percent strings, inferred page counts and local cover caches from
shared history; they can be rebuilt. Preserve original dates, unknown statuses, ignored fields,
discarded duplicates and malformed records in evidence. Booklist is not an additional opcode:
an external Booklist export requires the separate adapter and retained source identity.

## Open questions

- Should accepted copy returns become a first-class domain command now, or remain typed extras?
  This proposal chooses a command because the existing no-CAS path can lose a return decision.
- Should plan resolution receive a dedicated command rather than an ordinary conditional retry?
- Confirm product ordering for finished-year sections and whether undated history is sufficient
  for imported year-only Booklist rows; do not fabricate a day.
- Synthetic parity vectors still need to prove orphan notes, remove/re-add identities and
  invalid historical numeric values. No real-library contents were inspected.
