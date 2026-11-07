# reading.saved

Proposed 0.3 port; [README](README.md) supplies common conventions/import provenance.
Source prefix `R` is `packages/Colophon/Sources/ColophonReading/`; `A` is `apps/suite/Later/`.
This namespace has **36 advertised 0.1 kinds**, not just captured URLs. URL-free documents,
metadata-only imports, retained originals, annotations and graph histories must survive.
`source.native/nativeSource.preserve` is a separate namespace and is explicitly outside these
36; its pointers/evidence must be retained, not reinterpreted as reading.saved operations.

## 0.1 item and content operations

Canonical joint projection: `R/ReadingLibrary.swift`; bare links can use the fast path in
`R/SavedShelf.swift`, but any other kind forces joint source/deletion arbitration. Tool schemas
in `R/SavedLinks+Spec.swift` advertise only capture/state/metadata. Deletion, content and most
other kinds are typed-service writes, not missing or unused history. Field-level writer checks
are not necessarily fold checks. Missing/unknown fields remain in signed history even where
the old projection does not expose them.

| Kind | Payload | Validation/fold/conflicts |
| --- | --- | --- |
| `capture.link` | `item:ID,url:Text,title:Text`; extras including `added:Number,consumption,retention,author,summary,collection:Text,tags:Text[]` | Fold requires item/url, first existing item wins, title defaults URL; extra.added finite Unix seconds overrides operation date. Initial retention defaults saved. Unknown capture fields retained in extra. No HTTP URL validation in bare fold. |
| `item.setState` | `item:ID,consumption:Text?,retention:Text?,expect:Rev?`; internal `archiveImportCompleted:Text?`, `contentRestoreCompleted:Text?` | Existing item; stale string expect records conflict; supplied string values replace (unknown values accepted by fold), advances item revision/activity. The two completion markers affect web/native extras respectively. |
| `item.editMetadata` | `item:ID,title,author,summary,collection:Text?,tags:Text[]?,expect:Rev?` | Existing item, same CAS; supplied title and known metadata only. All-string tags trimmed, blanks/deduplicates removed and sorted, empty clears. Unknown edit fields not merged into old projection. |
| `item.delete` | `item:ID,expectActivity:Rev` | v1/app-or-device, exact two keys, established item, not already deleted. **Fold accepts a structurally witnessed earlier activity**, not necessarily latest current activity; service preflight uses current activity. Tombstones exact occurrence, no undelete; later content/state edits conflict and remain retained. |
| `content.install` | `item,title:Text,manifest:Version,added:Number?,extra:JSON?,create:Bool?,select:Bool?,expect:Rev?` | v1/app-or-device, valid manifest; item≤1,024 bytes, nonempty title≤16 KiB. Existing item requires exact item head; absent requires create=true. Reject metadata-only/excerpt transition through this kind. Retain immutable version; selects unless false. Same version ID with changed metadata/provenance invalid. |
| `content.select` | `item:ID,version:ID,expect:Rev` | Existing retained version; compare **source selection** head, not item revision. Changes selected version only. |
| `content.position` | `item,version:ID,position:Position,expect:Rev?` | Version must exist; optional string expect compares position head. Validate page/passages shape; ordered replacement may move backwards. |
| `content.note` | `item,version:ID,note:RetainedNote,expect:Rev?,originalAuthor:Text?` | Existing source; immutable source version per note; new note requires absent expectation, existing note exact expectation. Tombstoned note cannot return. Optional originalAuthor≤1,024 bytes is historical claim. |
| `content.removeNote` | `item,note:ID,expect:Rev` | Existing note and exact revision; permanent per-item note tombstone. |
| `content.images` | `item,version:ID,assets:Asset[],capture:ImageCapture,expectSource:Rev` | Exact source selection head;≤20 unique assets and≤40 MB/batch; validate source/version/candidates/coverage. Existing image identity can re-seal but cannot change plaintext or evidence. Updates asset/capture projection, not selection. |
| `content.readerMetadata` | `item:ID,metadata:ReaderMetadata,record:SnapshotItem?` | New item only, except deleted-history importer. Derived item ID must match provenance. Creates source-only item with no invented original/passages. Optional restored snapshot must match metadata, no content/notes/assets. |
| `content.externalExcerpt` | `item:ID,excerpt:ExternalExcerpt,record:SnapshotItem?` | New Readwise excerpt-only occurrence, no URL/original. Shape and source-derived identity validation; optional snapshot must agree. Source-only notes cannot claim an exact original location. |
| `content.attachReaderOriginal` | `item:ID,metadata:ReaderMetadata,manifest:Version,expect:Rev,expectActivity:Rev` | Exact item AND activity heads; existing metadata-only item must match original metadata; matching Reader document/provenance. Installs/selects reviewed original without converting imported highlights to newly authored notes. |
| `content.restore` | `item:ID,record:SnapshotItem,manifests:Version[],assets:Asset[]?,metadata:ReaderMetadata?,expectActivity:Rev?,archiveDigest:Digest?,restoreDigest:Digest?` | Exact activity including nil for absent item.≤1,024 unique manifests matching snapshot; selected/position/notes refer to those versions;≤10k notes,≤16,384 assets,≤1,024 captures. Native vs web identity/source provenance must agree. Replaces retained content snapshot while respecting existing note tombstones; malformed graph rejected. |
| `content.restoreDeleted` | `item:ID,history:DeletedHistory,manifests:Version[],assets:Asset[]?,metadata:ReaderMetadata?,excerpt:ExternalExcerpt?,checkpointSources:{Digest:BlobRef}` | v1/app-or-device and namespace-bound. Restores **dead history**, not a live item. On identity collision retains competing local/imported histories and marks complete export blocked. Invalid/unknown nested evidence cannot be silently decoded away. |

State writer enums: consumption `notStarted|inProgress|doneEnough|completed|abandoned`;
retention `captured|saved|chosen|resurface|released`. `released` is archive, not deletion.
Capture order is admitted sequence descending, not author time. Item revision, source revision,
activity revision, position head and per-note head are deliberately different. The old
`content.install` existing-item path does not simply advance every one of these heads.
Use the actual source fold to classify import outcomes rather than generic last-write-wins.
Sources: `R/SavedLinks.swift`, `ReadingContent.swift`, `ReadingContentService.swift`,
`ReadingItemDeletionService.swift`, `ReadingRecoveryKnownShape.swift`, `ReadingContentTransfer.swift`.

### Referenced 0.1 payload types

These are semantic Swift Codable shapes; enum associated values use the old Swift codec.
Import through that codec, preserving original bytes and unknown nested fields, rather than
guessing a new JSON discriminator. The linked source files own any deeper extraction formats.

- `BlobRef={digest,plain:Digest,epoch:Int,size:Int}`. Ciphertext digest/epoch change on reseal;
  plaintext digest and anchors do not. `Version` (`R/RetainedReadingVersion.swift`) is
  `{id,original:BlobRef,metadata:BlobRef,mediaType:Text,origin:ReadingOrigin,capturedAt:Date,
  extractionVersion:Int,pageCount:Int?,coverage:Text,readerProvenance:ReaderProvenance?}`.
  ID hashes `retained-reading-v1:<original.plain>:<metadata.plain>`; extractionVersion=1;
  media types PDF/plain/HTML/RFC822/XML; PDF iff pageCount present (1…10,000), metadata≤16 MB,
  positive bounded blob sizes, coverage≤4,096 bytes. Original maximum comes from
  `packages/MarginaliaCore/Sources/MarginaliaReaderCore/DocumentImport.swift`.
- `Position = page(Int) | passage(id:Text,offsetUTF16:Int)`;
  `RetainedNote={id,location:page(Int)|text(passageID,startUTF16,lengthUTF16),quote,text:Text,created:Date}`
  (`R/RetainedReadingNote.swift`). Fold validates page/range shape against manifest; source
  service additionally validates exact bytes, passage identity, UTF-16 boundaries and quote.
- `Asset={candidate:Candidate,blob:BlobRef,mime:Text,width,height:Int,observedURLs:Text[],capturedAt:Date}`;
  `Candidate={id,itemID,version:Text,index:Int,baseURL:Text?,sourceURL,alt:Text,afterPassageID:Text?}`
  (`R/RetainedReadingAsset.swift`). Candidate ID hashes item/version/index/URL; index<128;
  URL validated; alt≤4,000 bytes. JPEG/PNG/GIF/WebP, dimensions>2≤10,000,≤25M pixels;
  redirect list 1…6, unique, begins at sourceURL. `ImageCapture={id,itemID,version,created:Date,
  results:[{candidate,outcome:ReadingImageOutcome,reason:Text?}]}` (`R/ReadingImageCapture.swift`).
- `ReaderMetadata={version:1,provenance:ReaderProvenance,values:{title,author,summary,sourceName:Text,
  category,sourceLocation,url:Text?,firstOpened,lastOpened,published:Date?,tags:Text[],suppliedFraction:Number?}}`
  (`R/ReadingReaderMetadata.swift`). `ReaderProvenance` in `R/ReadingReaderProvenance.swift`
  pins raw export/document identity; `suppliedFraction` is unanchored imported progress.
  `ExternalExcerpt={version:1,format:readwiseCSV,workKey,sourceRecordDigest:Digest,title,author:Text,
  amazonBookID:Text?,rawExport:BlobRef,importedAt:Date}` (`R/ReadingExternalExcerpt.swift`).
- `SnapshotItem` (`R/ReadingContentTransfer.swift`) is `{id,title,url?,added:Date,consumption?,retention?,
  extra:JSON,isNative:Bool,versions:PortableVersion[],selectedVersion:ID?,position:{version,position}?,
  notes:[{version,note,author}],assets:PortableAsset[],imageCaptures:ImageCapture[],
  readerMetadata:ReaderMetadataSnapshot?,externalExcerpt:ExternalExcerptSnapshot?}`.
  PortableVersion replaces original/metadata BlobRefs with digest+size, keeps origin/date/page/
  coverage/provenance; PortableAsset replaces blob with digest+size. The full snapshot supports
  versions 1…7, with optional deletedHistory only in the declared newer format.
  `DeletedHistory` (`R/ReadingDeletedHistory.swift`) retains deletion, frozen content/shelf,
  checkpoints and claimed history; it is not a resurrection request. Full schema supplement
  [source models](reading.saved-models.md) lists its retained fields and nested import records.

## 0.1 Safari kinds

Sources: `R/SafariReading.swift`, `SafariReadingRequest.swift`, `SafariReadingActivityRequest.swift`,
`SafariReadingCheckpointClaims.swift`, `SafariReadingService.swift`.

| Kind | Payload | Fold and validation |
| --- | --- | --- |
| `safari.checkpoint` | `item,libraryID:ID,request:SafariRequest,commandDigest,sourceDigest:Digest,source:BlobRef,archiveOriginal:ArchiveCheckpoint?,archiveDigest:Digest?` | Unique op ID, v1, authenticated library match, app/device; exact source/request digests. Omitted passages may resolve from earlier validated source workspace. Signer/request UUID dedup; changed request digest rejected. Session sequence≤previous is receipted stale. Item must be derived safari URL ID or prior captured normalized URL. Retain source and notes even when not advancing selected reading. |
| `safari.activity` | `libraryID:ID,activity:Activity,commandDigest:Digest` | Unique op ID/v1/app-device; digest and library; observedAt≤op.created+30s; matching successful same-author checkpoint request/source/session. Request dedup; higher session sequence wins. Presence only, no content mutation. |
| `archive.select` | `item:ID,checkpoint:Rev,expect:Rev` | App/device, existing checkpoint belongs to item, exact Safari state revision; changes selected checkpoint and shared item revision. |

`SafariRequest={requestID,sessionID:UUID,sequence:Int,sourceURL,title:Text,passages:Passage[],
position:{passageID,offsetUTF16:Int},notes:SafariNote[],observedAt:ISOText,active,contextOptIn:Bool,
translations:{passageID:Text}?}`. Legacy singular `translation` is accepted by decoding.
`Passage={id,text,kind:Text,imageURL:Text?}`;
`SafariNote={id,passageID:Text,startUTF16,lengthUTF16:Int,quote,text:Text}`.
Total≤2 MiB, unique valid passage/note IDs, real UTF-16 boundaries and exact quote match,
nonempty title≤4,096 bytes, normalized URL≤8,192 bytes; sequence 0…2^53−1. Translation
references existing passages and each text≤256 KiB. `Activity={requestID,sessionID:UUID,
sequence:Int,sourceDigest:Digest,checkpointRequestID:UUID,observedAt:ISOText,active:Bool}`≤4,096
bytes, sequence>0. ArchiveCheckpoint retains author, optional itemID/noteOrigins, request and
isSelected (`R/SavedReadingArchive.swift`).

Old selection is exceptional: `(request.observedAt,op.created,op.clock,op.id)` and manual state
dates decide whether a checkpoint advances reading. An advancing checkpoint sets inProgress
and may create captured item. Notes are keyed by author/note ID and retain exact source digest.
Context expires 90 seconds after both observation/import, requires opt-in and current selection.
These old time-dependent semantics must be evaluated for import; **new reducer ordering must
not copy them**, and historical presence must never become a live context lease.

## 0.1 feed, annotation, view, review and question kinds

All listed graph/service kinds except the original feed operations are app/device fenced in
their projections. They share admission but have separate heads, receipts and validation.

| Kind / source | Payload | Fold/validation/conflicts |
| --- | --- | --- |
| `feed.follow` — `R/ReadingFeeds.swift` | `feed:ID,url,title:Text,folders:Text[][],expect:Rev?` | FeedSubscription URL-derived ID, valid address, title≤1,024 bytes,≤100 valid folder paths. New requires no string expect; refollow requires currently unfollowed and exact head. |
| `feed.unfollow` — same | `feed:ID,expect:Rev` | Followed existing source, exact head; reversible. |
| `feed.organize` — same | `feed:ID,folders:Text[][],expect:Rev` | Followed source, exact head, valid bounded folders. |
| `feed.refresh` — same | `feed:ID,response:BlobRef,entries:FeedEntry[],expect:Rev,title:Text?,omitted:Number?` | Followed/exact head; response≤5 MB with hex digests;≤500 unique valid entries. Merge arrivals, response recency window 100, entry window 5,000, prune expired browse rows; kept documents unaffected. Updated source head/date. |
| `feed.restore` — `R/ReadingFeedArchive.swift` | `feed:ID,archive:{record:FeedArchiveSource,refs:{Digest:BlobRef}}` | App/device only, source must be absent; validate complete archive and re-sealed response graph. Restored source preserves followed/folders/window; no new content capture. |
| `annotation.revision` — `R/ReadingAnnotationState.swift` | `revision:NoteRevision,expectActivity:Rev\|null?` | Shape, signer/library/request-derived revision ID, request reuse, parents/digests/immutable origin checked. Optional activity CAS. DAG retains concurrent heads, missing-parent/collision diagnostics; any valid delete is terminal. |
| `annotation.tags` — `R/ReadingAnnotationTagFold.swift` | `change:TagChange,expectActivity:Rev\|null?` | Request-derived identity, optional activity CAS; targets must be live at event point. Ordered membership decision per thread/tag, retained history. |
| `annotation.restore` — `R/ReadingAnnotationSnapshot.swift` | `archive:{records:NoteRecord[],sources:SealedSource[],diagnostics:Diagnostic[],expect:Rev?,digest:Digest,tagHistory:TagRecord[],tagDecisions:TagDecision[]}` | Exact annotation activity; graph/source/tag closure and archive digest, duplicate provenance validation. Preserves imported signers as claims, not live authority.≤100k records/sources/diagnostics; portable snapshot≤32 MB. |
| `view.revision` — `R/ReadingSavedViews.swift`, `ReadingSavedViewState.swift` | `revision:ViewRevision` | UUID root/revision IDs, author matches signer, name nonblank≤120 characters;≤1,024 sorted unique parents; one root, parent graph, no edits after deleted parent. Concurrent leaves retained; any valid deletion terminal; collision/unresolved graph blocks usable current. |
| `view.restore` — same, `ReadingSavedViewArchive.swift` | `revisions:ViewRevision[],provenance:{ID:Text[]}?` | One view graph≤1,025 revisions; complete DAG validation; historical signer chain starts with declared author and≤63 labels. No authority restoration. |
| `review.change` — `R/ReadingHighlightReviewState.swift` | `change:ReviewChange,evidence:NoteRecord?` | App/device, request-derived identity; action-specific targets, exact note evidence, undo targets prior revisited/passed choice. Ordered decisions; retains immutable history, budgets and diagnostics. |
| `review.restore` — same, `ReadingHighlightReviewSnapshot.swift` | `snapshot:ReviewSnapshot` | Validate complete history, decision groups and references; idempotent snapshot digest; preserve imported source settings separately from local enablement. |
| `answer.keep` — `R/ReadingQuestionAdmission.swift`, `PreparedReadingAnswerKeep.swift` | `packet:{answer:ReadingAnswer,custody:EvidenceCustody}` | App/device, metadata library/writer match authenticated envelope, source/note closure and byte budget, request/body digest receipt. Immutable answer and retained evidence, no model execution. |
| `answer.visibility` — `PreparedReadingQuestionChange.swift`, `ReadingQuestionProjection.swift` | `packet:{value:visibility(AnswerVisibility),custody:EvidenceCustody}` | Metadata/signature binding, exact answer and parent graph, visibility-group claims, empty custody for ordinary visibility; hidden/revealed is reversible, not deletion. |
| `connection.change` — same, `ReadingConnectionRevision.swift` | `packet:{value:connection(ConnectionRevision),custody:EvidenceCustody}` | Immutable source endpoints and note refs, relation/reason/retraction branches, complete evidence closure, retained concurrent heads. |
| `question.restore` — `PreparedReadingQuestionRestore.swift` | `packet:{metadata,sourceLibraryID,answers,visibility,visibilityGroups,connections,sourceDigest,custody}` | Validate paired answer/connection histories and source digest, exact custody, collision/replay checks; missing dependencies deferred, never trusted as fabricated local authors. |
| `magazine.subscription` — `R/ReadingMagazineSubscriptionState.swift` | `revision:SubscriptionRevision` (only top-level key) | v1/app-device, exact nested roundtrip, author/library match, UUID/parent/generation and dates validated. Current winner by generation then author then ID, **not timestamp**. |
| `magazine.subscriptionRestore` — same, `ReadingMagazineSubscriptionArchive.swift` | `archive:{version:1,revisions:SubscriptionRevision[]}` (only key) | Valid complete graph; historical provenance retained. Unknown subscription-prefixed kinds, unreadable/malformed values or collisions make state invalid and new writes/export fail closed. |

`FeedEntry={id,title,url?,publisherIdentity,author,summary,published:Date?,response:BlobRef?}`;
limits ID128/title4096/URL8192/publisherIdentity8192/author1024/summary4096 bytes. Supplied response
is overwritten by the refresh's response. `omitted` 0…500 is converted to integer.
`ViewRevision={id,viewID,parents:ID[],name,query:ViewQuery,deleted:Bool,author,created:Date}`.
`ViewQuery={version:Int,shelf:all|readingNow|unread|finished|archive,search,source:Text,tag,collection:Text?,
kind:all|web|pdf|text|htmlFile|email|feed|originalMissing,consumption,retention:Text?,
availability:any|savedText,sort:newest|oldest|title|author}`. v1/v2 supported, originalMissing needs
v2; incompatible shelf/state combinations invalid (`R/ReadingViewQuery.swift`).

`NoteRevision={id,threadID,parents:[{id,digest}],action:create|edit|relocate|resolve|delete,
source:NoteSource,anchor:NoteAnchor,text:Text,created,recorded:Date,origin:NoteOrigin,requestID:UUID}`
(`R/ReadingNoteRevision.swift`, `ReadingNoteSource.swift`). Sources pin native version, Safari
digest, Reader metadata digest or external excerpt digest. Anchors are text(passageID,startUTF16,
lengthUTF16,quote), page(index), item or unresolved(quote,location,reason). Item-only anchors
require text; source-only cannot claim page/text. Parent refs exact,≤1,024; text range bounded
to 8M UTF-16 units, quote≤256k bytes, page<10k. Edits keep source/anchor; relocation keeps text;
delete retains a reviewed branch; resolve must cover reviewed parents. Origin local/copyOf/
legacyNative/legacySafari/reader/readwise is immutable lineage, not authenticated new authorship.
Annotation text is at most 64,000 UTF-8 bytes in this old model; create has no parents,
edit/relocate exactly one, other actions require at least one. `NoteRecord={revision,writer,operationID,provenance:authenticated|legacy|imported,
attributedAuthor?,importedBy?,importOperationID?}`. Legacy content.note/removeNote and Safari
notes are normalized into this annotation graph; don't count them twice during import.

`TagChange={version:1,id:Digest,threadIDs:ID[],tag:Text,included:Bool,requestID:UUID}` (1…1,000
targets); TagRecord/TagDecision preserve membership history and chosen reference.
`ReviewChange={version:1,id:Digest,requestID:UUID,action:enable|disable|revisited|passed|exclude|include|undo,
observedAt:Date,threadID:ID?,revision:NoteRef?,undoing:ReviewRef?}`. Enable/disable have no
targets; include thread only; revisited/passed/exclude need thread+revision; undo also needs
prior reference. Review candidate eligibility excludes deleted/conflicted notes and missing items.

`ReadingAnswer={metadata,question,evidence,claims,engine,runtime,promptRevision}`;
`Metadata={libraryID:ID,id,requestID:UUID,writer:ID,created:Date,suppliedCreatedAt:Text?}`;
`AnswerVisibility={metadata,answer:QuestionRef,parents:QuestionRef[],hidden:Bool}`;
`ConnectionRevision={metadata,root:QuestionRef?,parents:QuestionRef[],source,target:{source:NoteSource,note:NoteRef?},
relation:related|supports|challenges|expands,reason:Text,retracted:Bool}`.
`QuestionRef` is an exact content reference, not an item revision. `EvidenceCustody` retains
sealed sources and note revision records; source references never broaden current read scope.
Question commands≤128 MB; portable section≤32 MB,≤100k records, aggregate custody≤200k sources/
bindings and≤192 MB. Preserve these limits in the import decoder; do not send them through a
hot FFI query. Detailed nested fields are in [source models](reading.saved-models.md).

`SubscriptionRevision={id,libraryID,parent:ID?,generation:Int,author:ID,value:{publication,
status:unknown|active|paused|expired|cancelled,plan:unknown|digital|print|printAndDigital,
accessUntil:Date?,updatedAt:Date}}`; generation1…1,024 and parent absent iff generation1,
canonical whole-second dates. Publication is a defined magazine identity
(`packages/MarginaliaCore/Sources/MarginaliaReaderCore/MagazinePublication.swift`). These are
user-declared subscriptions, never publisher credentials or proof of access.

Derived rather than new history: shelf finished/archive/reading-now flags, sorted lists,
counts, source-only flags, selected-source availability descriptors, annotation leaf sets,
conflict badges, review eligibility/decision indexes, feed browse windows, saved-view results
and question visibility/connection heads. `ReadingLibrary` does not itself fold feed/view/
annotation/review/question/subscription collections: their separate projections consume the
same admitted log. Losing branches, rejected known payloads, portable provenance, overwritten
metadata, old response bytes and unknown kinds remain history/evidence even when absent from
the current visible item. Source bytes require host verification; a fold-derived descriptor
must not be labelled as a verified local original.

## Usage inventory and heat

| Surface / source | Writes | Reads and heat |
| --- | --- | --- |
| `A/AddLinkSheet.swift`, `SaveLinkIntent.swift`, `LaterShareInbox.swift`; `apps/suite/LaterShareExtension/ShareViewController.swift` | capture.link in app/intent; extension writes destination-bound inbox envelope, not direct replica | Admission/receipt check on ingest/background/intent. Share UI only local staging. |
| `A/LaterHome.swift`, `SavedRowActions.swift`, `LaterLinkDetails.swift` | setState/editMetadata; deletion via `Deletion/LaterReadingDeletionWorker.swift` | Cached ReadingLibrary/list filters/counts per namespace revision and render/scroll; fresh single item before action. |
| `A/LaterReaderDestination.swift`, `LaterDocumentReaderDestination.swift`, `LaterDocumentReadingWorker.swift`, `SafariContinuationReader.swift` | content.install/select/position, setState; native source/annotation services | Single selected source, position and visible passages on open/scroll; coarse progress save, not whole fold per frame. Source blobs decoded on worker, rendering local. |
| `A/LaterDocumentWorker.swift`, `LaterReadingImageWorker.swift`, `LaterReaderMetadataWorker.swift`, `LaterNativeImportWorker.swift` | content.install/images/readerMetadata/externalExcerpt/attachReaderOriginal/restore through services | Background preparation/verification and post-write receipts; raw PDF, metadata and image bytes off main render path. Native import also needs separate source.native access. |
| `A/LaterSafariSourceWorker.swift`, `SafariReadingController.swift`, `LaterSafariBridge.swift`; `R/SafariReadingService.swift`, `SafariReadingInbox.swift`, `SafariReadingActivityInbox.swift` | safari.checkpoint/activity and archive.select through service | Foreground inbox drain, exact source context and selected checkpoint; presence is transient host state. SafariWebExtensionHandler stages inbox records, not direct domain writes. |
| `A/LaterAnnotationWorker.swift`, `LaterAnnotationWorker+Relocation.swift`, `LaterHighlightsWorker.swift`, `LaterHighlightsExportWorker.swift` | annotation.revision/tags/restore; legacy content.note/removeNote retained by service compatibility | Threads/heads/source context, tag list and paged highlight rows on revision/action; exact source resolve on selection; export background. |
| `A/LaterHighlightsReviewWorker.swift` | review.change/restore | Bounded eligible review queue and history on user action; eligibility depends on annotation/item indexes. |
| `A/LaterFeedsView.swift`, `LaterFeedSourceView.swift`, `LaterFeedWorker.swift` | feed.follow/unfollow/organize/refresh; keeping an arrival installs native content | Source/arrival rows on render/scroll; network refresh background, keep on action. |
| `A/LaterSavedViewWorker.swift`, `LaterSearchIndex.swift` | view.revision; restore via archive | Saved definitions and local indexed full-text facts on revision/filter; no repeated raw blob search per row. |
| `A/Google/LaterGmailWorker.swift`, `LaterICloudNewsletterWorker.swift` | capture retained newsletter through ReadingContentService | Background import; mail credentials/local account state outside operations. |
| `A/Magazines/LaterMagazineSubscriptionWorker.swift` | magazine.subscription/subscriptionRestore | Current per-publication value, archive and save review; no per-scroll network authorization. |
| `A/Questions/Feature/LaterQuestionFeatureWorker.swift`, `Questions/LaterQuestionPublicationWorker.swift`, `Questions/LaterQuestionPendingWorker.swift`, `Questions/History/LaterQuestionHistoryWorker.swift`, `Questions/Selection/LaterQuestionSelectionWorker.swift` | answer.keep/visibility, connection.change, question.restore via typed services | Bounded prepared evidence, current heads, answer/connection history on revision/filter; model work and durable pending publication are host workers. |
| `A/LaterPortableArchive.swift`, `LaterTransferWorker.swift`, native/Reader/Readwise import workers | capture/state and all relevant restore kinds | Full export/import intentionally background; verifies retained history/bytes, not an interactive read API. |
| `A/LaterWidgetPublisher.swift`, `LaterWidgetReadingSelection.swift`, `LaterWidgetProgressWorker.swift`; `apps/suite/LaterWidgets/LaterWidgets.swift`, `Shared/LaterWidgetSnapshot.swift` | No direct widget domain mutation; app publishes local snapshot | Cached selection on revision; local source progress worker; widget timeline/render reads snapshot. Never refold or verify full document from widget body. |
| Legacy `apps/apple/App/Library/LibraryOverview.swift`, `ReadingSessionView.swift`, `apps/apple/App/Intents/ReaderIntents.swift`, `apps/apple/ShareExtension/ShareViewController.swift`, `apps/apple/App/Library/ActivityWidgetPublisher.swift` | Older Marginalia journal capture/reading/annotation mutations and local ingress/snapshots | Legacy reading UI/intent/widget projections; not direct SavedLinks kinds. |
| Android `android/app/src/main/kotlin/xyz/marginalia/android/AppModel.kt`, `ShareActivity.kt`, `reader/ReaderScreen.kt`, `library/LibraryScreen.kt`, `AnnotationsScreen.kt`, `HighlightsScreen.kt`, `FeedFoldersScreen.kt`, `MagazinesScreen.kt`, `store/Capture.kt`, `FeedRefresh.kt` | Older journal capture/position/state/annotation/feed/publication commands | Compose render/scroll, background sync/feed work, reader local geometry and periodic progress. No ColophonReading fold implementation. |

Additional ingress details and payload model fields are in the supplement.
Heat is qualitative static analysis.
The suite already caches some projections: 0.3 should preserve that behavior while removing
whole-state copies across FFI. Legacy Android/Apple journal is a separate input format.

## Proposed 0.3 design (24 kinds)

Clean commands, v1. All payload unknown fields are retained per README; controls never become
metadata. App/device-only gates remain for content installation, destructive actions, graph
review and explicit acceptance. Pure reducers validate structure/identity/closure; the host
validates bytes and current authorization. A missing blob is never a blank article.

| Kind | Payload | Effect and conflict rule |
| --- | --- | --- |
| `capture` | `id,title;url:URL?,consumption:Text?,retention:Text?` | Create occurrence; permits URL-free native item, no dedup by URL. This extends preview capture's required URL and needs coordination. |
| `setState` | `id;consumption:enum?,retention:enum?,expect:Rev?` | Item state CAS, preserve missing values; explicit nullable initial state only at capture. |
| `editMetadata` | `id;title,creator,summary,collection:Text?,tags:Text[]?,expect:Rev?` | Metadata CAS; creator avoids authenticated author collision; empty tags/collection clear. |
| `delete` | `id,expectActivity:Rev` | Exact **current** item activity required, permanent tombstone. Structural old witness acceptance is not the new rule. |
| `retainSource` | `id,item,manifest:SourceManifest;select:Bool=false,expect:Rev?` | Immutable version, validate typed metadata/Blob descriptors, exact source head for selection; item must exist. No extraction inside reducer. |
| `selectSource` | `item,source:ID,expect:Rev\|null` | Exact source selection head; retain all prior versions. |
| `position` | `item,source:ID,position:AnchorPosition;expect:Rev?` | Separate position head CAS; validate source binding and range shape; deliberate backwards reading allowed. |
| `reviseAnnotation` | `id,thread,item,source:ID,parents:Rev[],action:create\|edit\|relocate\|resolve\|delete,anchor:Anchor,text` | Immutable DAG nodes, exact referenced parents; concurrent siblings kept. Resolve names all observed heads; terminal delete, late alternatives retained; explicit copy-as-new for recovery. |
| `tagAnnotations` | `id,threads:ID[],tag,included:Bool;expect:Rev?` |≤1,000 live threads, atomic membership decisions and receipt; ordered per thread/tag. |
| `followFeed` | `id,url,title,folders:Text[][];expect:Rev?` | New or refollow with head match; namespace-wide ID stable. |
| `unfollowFeed` | `id,expect:Rev` | Reversible exact head. |
| `organizeFeed` | `id,folders:Text[][],expect:Rev` | Exact feed head; bounded paths. |
| `refreshFeed` | `id,response:Blob,entries:FeedEntry[],expect:Rev;title:Text?,omitted:Int?` | Keep old bounded 100-response/5,000-entry browse window; descriptors only, no fetch; item retention independent. |
| `reviseView` | `id,view,parents:Rev[],name,query:ViewQuery,deleted:Bool` | Root or immutable revision; all branches retained, terminal deletion; strict query AST validation. |
| `changeReview` | `id,action:enable\|disable\|revisited\|passed\|exclude\|include\|undo;thread:ID?,annotation:Rev?,undoing:Rev?` | Action-target validation, receipt, immutable decision history. Imported enablement is not local opt-in. |
| `keepAnswer` | `id,question,claims:Claim[],evidence:EvidenceRef[],engine,runtime,promptRevision` | Immutable retained answer, source/note custody references; app/device action separate from generated content attribution. |
| `setAnswerVisibility` | `id,answer:ID,parents:Rev[],hidden:Bool` | DAG of reversible visibility; concurrent choices retained with conflict status. |
| `reviseConnection` | `id,connection:ID,parents:Rev[],source,target:Endpoint,relation:enum,reason,retracted:Bool` | Exact endpoints/source evidence; immutable revision DAG, concurrent heads retained. |
| `setMagazineSubscription` | `id,publication:ID,status:enum,plan:enum;accessUntil:Instant?,expect:Rev?` | Per-publication CAS; retain full competing values instead of 0.1 generation tie-winner. No access credential. |
| `retainSourceMetadata` | `id,item,kind:readerMetadata\|externalExcerpt,value:JSON,raw:Blob` | Typed source-only record, immutable raw provenance; item has no original until explicit attach. Value validated with declared model version. |
| `attachOriginal` | `item,metadata:ID,manifest:SourceManifest,expect:Rev,expectActivity:Rev` | Exact metadata/source/activity; reviewed source transition; no invented annotation anchors. |
| `retainImages` | `item,source:ID,assets:ImageAsset[],coverage:ImageCoverage,expect:Rev` | Atomic source-head check, immutable source candidates and bounded blobs; unavailable download status separate. |
| `captureReading` | `id,item,source:SourceManifest,position:AnchorPosition,notes:AnnotationSeed[],expect:Rev\|null` | Atomic durable browser checkpoint: exact item activity, source, position and pinned new note seeds. Host ingress session/sequence receipts outside shared semantic state. No active/presence fields. |
| `selectReadingCheckpoint` | `item,checkpoint:ID,expect:Rev\|null` | Exact selection head; picks retained checkpoint, never reactivates its browser session. |

All shared item-affecting mutations, including annotation edits/tags, advance item activity;
state/metadata/source/position/annotation heads remain independent. New `expect` semantics
are explicit (README), so not every old revision maps to the last emitted operation.
Known invalid input must produce diagnostics without partial changes. DAG dependency queues
and reverse edges are maintained incrementally; arriving prerequisites trigger bounded
dependent re-evaluation. An earlier-order operation invalidates the engine prefix/checkpoint,
not merely an app revision counter. Unknown future graph kinds retain history and report
unsupported capability; they cannot silently certify a complete export.

`SourceManifest={id,original:Blob?,metadata:Blob,mediaType,origin:JSON,capturedAt:Instant,
extractionVersion:Int,pageCount:Int?,coverage:Text}`; original required except explicitly
declared browser-extraction sources. New original/extraction IDs are content-derived from
plaintext hashes with a versioned purpose. Import may preserve old content IDs through map.
`AnchorPosition={kind:page,index:Int}|{kind:passage,id:ID,offsetUTF16:Int}`;
`Anchor={kind:text,passageID,startUTF16,lengthUTF16,quote}|{kind:page,index}|{kind:item}|
{kind:unresolved,quote,location,reason}`. `AnnotationSeed={id,anchor,text}`.
`ImageAsset` retains old candidate fields with Blob and source ID; `ImageCoverage` is the
bounded candidate outcome list, distinguishing retained source evidence from local downloads.
`Endpoint={item,source:ID,annotation:Rev?}`; `EvidenceRef={source:ID,annotation:Rev?,anchor:Anchor?}`;
`Claim={text:Text,citations:EvidenceRef[]}`. Large exact custody snapshots/diagnostics live in
encrypted evidence blobs, addressed by digest, not copied into every new operation.

Keep source payload bounds listed above and ≤256 KiB inline note/answer text; new commands
≤1 MiB, exception-free. Chunk large import graphs into bounded commands in topological order
and checkpoint the import manifest. A historical atomic snapshot is published only after all
parts and its receipt are durable; SDK migration mode hides partial results. Never weaken
source validation to make a chunk fit. Feed responses/originals, transcripts, PDF, extracted
passages, MIME originals, image and ink data are blobs. Search and reading-progress indexes
are local digest-keyed caches; export remains streaming background work.

Do not replicate browser activity leases, current tab/selection, translation-render state,
model enablement, credential tokens, magazine cookies, download reachability, file bookmarks,
scroll pixels, widget snapshot files, import staging directories or retry timers. A retained
translation or source observation already in old signed history stays evidence. Source.native
capsules require their own namespace keys and migration plan; never widen reading.saved grants.

## Named queries (19)

`ItemRow={id,title,creator?,url?,kind,consumption?,retention?,added,sourceStatus,progress?,
noteCount,conflictCount,revision}`. Source status is descriptor state (none/sourceOnly/retained);
host byte state is separate. `AnnotationRow={id,thread,item,source,anchorPreview,textPreview,
heads:Rev[],deleted,conflicted,authorLabel,tags}`; previews bounded to 512 UTF-16 units, full
values retrieved only by single-record queries. Any head array too large returns count+cursor.

| Query(arguments) | Result value / ordering | UI path |
| --- | --- | --- |
| `items(query:ViewQuery,cursor?,limit?)` | Page ItemRow; requested sort then ID | Home/search/saved views, indexed filters; host savedText index joined by ID |
| `item(id,includeDeleted:Bool=false)` | `{item:Attributed,heads:{state,metadata,source,position,activity},selectedSource?,metadataOnly:Bool,extensions}` | Details, pre-write CAS, reader destination |
| `readingCounts(query?:ViewQuery)` | `{total,readingNow,unread,finished,archived,deleted,sourceOnly,notes,conflicts}` | Badges, empty-state headings |
| `sources(item,kind:versions\|images,source?:ID,cursor?,limit?)` | Page SourceManifest or ImageAsset descriptor, source creation order/ID | Source picker/images; never embedded blob bytes |
| `position(item)` | `{source,position,revision,updated}` or null | Reader resume, widget worker |
| `annotations(item?:ID,tag?:Text,includeDeleted:Bool=false,cursor?,limit?)` | Page AnnotationRow, touched descending/ID | Highlights and item notes |
| `annotation(thread,revision?:Rev)` | `{current:NoteRevision?,heads,headCount,deleted,sourceStatus,extensions}` | Editor/context; explicit revision gets full node |
| `annotationHistory(thread,cursor?,limit?)` | Page `{revision,parents,action,text,anchor,source,attribution,historical}` | Conflict/history review, fold order/ID |
| `feeds(followed:Bool=true,folder?:Text[],cursor?,limit?)` | Page `{id,title,url,folders,followed,revision,entryCount,omitted,refreshed?}` | Feed/folder list, title/ID |
| `feedEntries(feed,cursor?,limit?)` | Page `{id,title,url?,author,summaryPreview,published?,response}` | Arrivals, response/order descending then ID |
| `savedViews(includeDeleted:Bool=false,cursor?,limit?)` | Page `{id,name?,headCount,deleted,conflicted,revision?}` | Picker, name/ID |
| `savedView(id)` | `{heads:ViewRevision[],headCount,deleted,conflicted}` (bounded, excess via conflicts) | Edit/run definition |
| `reviewQueue(limit?=20)` | `{enabled:Bool,rows:AnnotationRow[],eligibleCount,decisionRevision}` | Review cards, deterministic last-choice order/ID; no wall-clock eligibility in reducer |
| `reviewHistory(thread?:ID,cursor?,limit?)` | Page `{id,action,annotation?,undoing?,attribution,observedAt?,historical}` | Review history/undo, admitted order |
| `answers(hidden:Bool=false,item?:ID,cursor?,limit?)` | Page `{id,question,claimCount,evidenceCount,sourceStatus,visibilityHeads,revision}` | Saved answers; creation order/ID |
| `answer(id)` | `{answer:Attributed,question,claims,evidence,engine,runtime,promptRevision,sourceStatus}` | Exact bounded answer; large evidence via blob descriptor |
| `connections(item?:ID,includeRetracted:Bool=false,cursor?,limit?)` | Page `{id,source,target,relation,reasonPreview,retracted,heads,conflicted}` | Connections list/history, touched/ID |
| `subscriptions(publication?:ID,cursor?,limit?)` | Page `{publication,status,plan,accessUntil?,revision,alternativeCount}` | Magazine subscription panels; publication/ID |
| `conflicts(object:ID,component?:Text,cursor?,limit?)` | Page `{operation,reason,expected?,found?,candidate,attribution,historical}` | Item/source/view/connection/subscription alternatives and migration diagnostics |

Long content text is read through a host `sourcePassages(source,cursor,limit≤100)` or PDF-page
API, verifying digest before serving and distinguishing missing/unavailable/invalid bytes.
Search uses a local index keyed by selected source/annotation revision; pagination joins a
bounded set of IDs to item summaries. Keep stable snapshot tokens across the host index/core
join; invalidate if either changes. UI scrolling never calls a full ReadingLibrary fold or
per-row source verifier. Counts update with mutations, not by enumerating operations.

## Every-kind import mapping

All 36 kinds have a disposition below. README mandates original operation ID, verified author
label, signed-body digest, admission/outcome and exact source archive retention. Restore
records also retain nested historical operation/revision IDs, signer chains, source roots,
portable archive digests and diagnostics. A nested claimed writer is never a restored signer.
Map existing annotations once through normalized thread identity; old content/Safari seeds
and later annotation revisions must join the same thread, not create duplicate highlights.

| 0.1 kind | Clean mapping / exclusions |
| --- | --- |
| `capture.link` | `capture`, metadata extras→editMetadata or extension fields; convert known initial consumption/retention and added-date claim explicitly. Non-HTTP old URL stays evidence if new URL validation fails. |
| `item.setState` | `setState` only for effective state mutation; completion marker is import receipt/evidence, never a new UI state. Stale writes retained as alternatives. |
| `item.editMetadata` | `editMetadata`, author→creator, preserve old normalized tags/collection and original unknown properties in evidence/extensions. |
| `item.delete` | `delete` using imported current activity after reproducing old outcome; retain old witnessed expectActivity as provenance. Later old records stay tombstone alternatives. Do not retroactively apply stricter new CAS to erase an old accepted deletion. |
| `content.install` | Capture missing item, retainSource, optional selectSource; preserve immutable source ID/bytes/provenance. Do not invent original for source-only records. |
| `content.select` | `selectSource` against mapped source head. |
| `content.position` | `position` with mapped source and position head; invalid anchors remain evidence, not zero-page defaults. |
| `content.note` | `reviseAnnotation` create/edit in normalized legacy-native thread; originalAuthor is historical attribution. Preserve source pin. |
| `content.removeNote` | `reviseAnnotation(action:delete)` for normalized thread; keep tombstoned source/history. |
| `content.images` | `retainImages`; re-seal valid image blobs, preserve coverage failures as evidence, local availability not copied. |
| `content.readerMetadata` | Capture source-only item + retainSourceMetadata(readerMetadata); raw export retained; supplied progress stays an unanchored claim, not position. |
| `content.externalExcerpt` | Capture source-only item + retainSourceMetadata(externalExcerpt); preserve raw CSV reference/IDs, never fabricate publisher original. |
| `content.attachReaderOriginal` | `attachOriginal` with mapped metadata/source/activity heads; preserve original reviewed provenance. |
| `content.restore` | Expand accepted snapshot into capture/retainSource/selectSource/position/reviseAnnotation/retainImages and metadata. Retain replaced/removed prior content in evidence; do not silently union stale snapshot versions. If snapshot replacement cannot map to terminal new note semantics, allocate explicit occurrence mapping and report it. |
| `content.restoreDeleted` | Import retained sources/history and terminal delete, never expose live item. Collision graphs and blocked export diagnostics remain in evidence; unresolved closure is an import gap. |
| `safari.checkpoint` | Retain source and normalized note revisions; reproduce historical selected position/inProgress only if old fold advanced it. Use captureReading/selectReadingCheckpoint with mapped heads when atomic shape fits; otherwise chunk under migration publication receipt. Preserve request/session/sequence/digests in evidence. Omitted passages require earlier source evidence; missing input cannot be synthesized. |
| `safari.activity` | Historical evidence only. Drop live presence/lease effect because it is device/session-local and expired/rebind-required. |
| `archive.select` | `selectReadingCheckpoint`, preserving chosen source/checkpoint and old revision map. No browser presence. |
| `feed.follow` | `followFeed`; exact old normalized ID/URL and folders. |
| `feed.unfollow` | `unfollowFeed`; preserve archived source descriptors. |
| `feed.organize` | `organizeFeed` for accepted folder change. |
| `feed.refresh` | `refreshFeed`, re-seal retained response; preserve all old response descriptors/evidence, even outside current browse window; no kept-item deletion. |
| `feed.restore` | Follow/refresh/organize/unfollow sequence reconstructs accepted source with explicit followed flag and browse order; archive/source digest receipt retained. |
| `annotation.revision` | `reviseAnnotation` with full parent/reference map, source, anchor, text and action; preserve all valid branches, diagnostics and immutable origin. |
| `annotation.tags` | `tagAnnotations` for accepted memberships; map thread IDs; invalid/later-deleted attempts remain evidence. |
| `annotation.restore` | Sources + topologically ordered reviseAnnotation/tagAnnotations for validated imported graph, preserve nested provenance/diagnostics/decisions and archive receipt. Never flatten to current note text only. |
| `view.revision` | `reviseView`, map parents; retain unresolved definitions rather than pick arbitrary winner. |
| `view.restore` | Topological reviseView commands plus signer-chain evidence; preserve terminal deleted views. |
| `review.change` | `changeReview` for durable decisions, with mapped annotation/undo refs. Old local enablement becomes historical preference, requires explicit destination opt-in before automatic resurfacing. |
| `review.restore` | Expand immutable review history/decision groups into evidence and mapped changeReview decisions; preserve imported source settings independently. |
| `answer.keep` | `keepAnswer`; re-seal exact custody source/note evidence, retain model/runtime/prompt and original metadata; no model call during import. |
| `answer.visibility` | `setAnswerVisibility`, map parent and answer references, preserve concurrent visibility decisions. |
| `connection.change` | `reviseConnection`, map exact source/annotation endpoints, parent/root refs and retraction branches. |
| `question.restore` | Topological keepAnswer/setAnswerVisibility/reviseConnection plus custody blobs and paired archive digest/group evidence. Deferred or invalid dependencies stay unresolved, never silently dropped. |
| `magazine.subscription` | `setMagazineSubscription` for old projected winner and complete historical alternatives. Preserve generation/parent/author tie order in evidence; importer cannot certify publisher access. |
| `magazine.subscriptionRestore` | Same per-publication normalization from validated archive; keep every old revision/parent and import receipt. If old state invalid/unreadable, do not turn it into empty current subscription values. |

Cannot infer unavailable originals, missing earlier Safari passages, broken anchor closures,
unreadable source.native capsules or unknown graph semantics. Retain source bytes/digests and
diagnostics and report incomplete migration. Unknown optional fields are not a reason to drop
the entire record; unknown semantic fields that the old verifier cannot preserve are.
Do not copy credentials or local browser/mail accounts. Derived counters, search/render caches,
widget files and download flags are excluded because they can be rebuilt locally.

## Open questions

- Coordinate proposed Blob, evidence sidecar and typed source descriptors with the core/FFI
  workers; 0.3 preview only implements URL items and cannot yet promise retained-content parity.
- Historical atomic restores can replace whole content snapshots; bounded decomposition needs
  an importer publication barrier and explicit old→new occurrence map. This is required work,
  not an already tested migration guarantee.
- Decide whether subscription concurrency should use complete alternatives (proposed) or keep
  a deterministic generation winner plus alternatives for display.
- Confirm exact current product handling of review enablement and Safari cross-device
  selection. New history must avoid author-date arbitration and transient presence operations.
- The nested source models and recovery protocols need synthetic vectors across snapshot
  versions 1…7, annotation versions 1…5, unknown keys and missing custody. Reading has the
  largest validation surface and lowest parity confidence until those vectors run.
