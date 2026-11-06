# Saved-reading source model supplement

This is part of the [reading.saved inventory](reading.saved.md), at the committed baseline
in [README](README.md). It supplies nested legacy payload fields used by restore and provenance
records. `R` means `packages/Colophon/Sources/ColophonReading/`; `C` means
`packages/MarginaliaCore/Sources/MarginaliaReaderCore/`. These are semantic schemas derived
from code, not exported personal data. Date/enum encodings use the original Codable decoder;
unknown keys must survive in retained bytes even when they cannot be interpreted.

## Retained originals and deleted history

| Model / source | Stored fields |
| --- | --- |
| ReadingOrigin — `R/ReadingOrigin.swift` | Enum file(name:Text), web(source:ArticleCaptureSource), feed(id:ID,entryID:ID,url:Text?), reader(documentID:ID,url:Text?). File origin has no fabricated URL; web origin is captured source evidence. |
| ArticleCaptureSource — `C/ArticleCaptureSource.swift` | requestedURL:Text, redirects:Text[]. resolvedURL is derived as last redirect or requestedURL, not another stored property. |
| ReadingReaderProvenance — `R/ReadingReaderProvenance.swift` | version:Int, documentID:Text, sourceRecordDigest:Digest, rawExport:BlobRef, sourceSavedAt:Date?, importedAt:Date. Reader raw bytes must reconstruct the claimed document; signature alone is not source verification. |
| ReadingReaderPortableProvenance — `R/ReadingReaderPortableProvenance.swift` | version:Int, documentID:Text, sourceRecordDigest:Digest, rawDigest:Digest, rawSize:Int, sourceSavedAt:Date?, importedAt:Date. Same semantic provenance without ciphertext/epoch binding. |
| ReadingReaderMetadataSnapshot — `R/ReadingReaderMetadataSnapshot.swift` | version:Int, provenance:ReadingReaderPortableProvenance, values:ReaderMetadata.Values (main spec). |
| ReadingExternalExcerptSnapshot — `R/ReadingExternalExcerptSnapshot.swift` | version:Int, format:readwiseCSV, workKey:Digest, sourceRecordDigest:Digest, title:Text, author:Text, amazonBookID:Text?, rawDigest:Digest, rawSize:Int, importedAt:Date. |
| ReadingDeletedHistory — `R/ReadingDeletedHistory.swift` | itemID:ID, shelf:SavedLinkTransfer.Record?, content:ReadingContentSnapshot.Item?, checkpoints:SavedReadingArchive.Checkpoint[], sourceDeletion:{itemID,operationID,expectedActivityRevision,authorID:Text,deletedAtEpochSeconds:Number}. Exact nested shape preservation rejects decoding that would silently remove evidence. |
| SavedLinkTransfer.Record — `R/SavedLinkTransfer.swift` | id:ID, url:Text, title:Text, added:Number?, consumption:Text?, retention:Text?, extra:{Text:JSON}. added is Unix seconds; external transfer supports bounded JSON/CSV/bookmarks/text, not additional operation kinds. |
| ReadingDeletedItemRestore — `R/ReadingDeletedItemRestore.swift` | Internal decoder, not an extra operation: extracts history/digest/checkpointSources and synthesizes a content kind/payload or shelf command from `content.restoreDeleted`. The operation itself retains item/history/manifests/assets/metadata/excerpt/checkpointSources. |

Deletion history is a frozen source occurrence. Recovery collision state is not an undelete.
`R/ReadingRecoveryKnownShape.swift`, `ReadingRecoveryPackageSemantics.swift`,
`ReadingRecoveryWitnessCodec.swift` distinguish understood structure, claimed causal history
and verified source bytes. A recovery package is not another reading.saved opcode and cannot
be imported by treating every embedded claim as an admitted operation. Unknown nested keys or
missing witness closure require retained evidence and an explicit gap.

## Feed archives

Source `R/ReadingFeedArchive.swift`:

- `Restore={record:Source,refs:{Digest:BlobRef}}` (the actual `archive` payload field).
- `Source={id,title,url:Text,folders:Text[][],followed:Bool,refreshed:Date?,currentResponse:Digest?,
  omittedEntries:Int,entries:Entry[],responses:Response[]}`.
- `Entry={id,title,publisherIdentity,author,summary:Text,url:Text?,published:Date?,responseDigest:Digest}`.
- `Response={digest:Digest,redirects:Text[]}`.

The service validates retained response bytes by parsing the feed and comparing entry fields,
not merely trusting the embedded titles. Archive limits include ≤10,000 sources,≤100,000 blobs,
≤8 MB source metadata and≤128 MB distinct response bytes; each response≤5 MB and parsed feed≤500
items. Fold-time restoredSource checks descriptors and graph consistency without network I/O.
Reconstruct original entry/response ordering explicitly; the browsing window is not the source
archive's preservation boundary.

## Annotation and review archives

| Model / source | Stored fields |
| --- | --- |
| ReadingAnnotationSealedSource — `R/ReadingAnnotationSnapshot.swift` | source:ReadingNoteSource, title:Text, native:RetainedReadingVersion?, safari:BlobRef?, unavailable:Bool, readerMetadata:ReadingReaderMetadata?, externalExcerpt:ReadingExternalExcerpt?. Exactly the matching source variant; unavailable forbids an invented retained source. |
| ReadingAnnotationSnapshot.Source — same | source, title, native:ReadingContentSnapshot.Version?, safariDigest:Digest?, safariSize:Int?, unavailable:Bool, readerMetadata:ReadingReaderMetadataSnapshot?, externalExcerpt:ReadingExternalExcerptSnapshot?. |
| ReadingAnnotationDiagnostic — `R/ReadingAnnotationState.swift` | id:ID, reason:Text, operation:ColophonOperation, writer:ID, record:ReadingNoteRevisionRecord?, importedBy:ID?. Retained failed attempt, not executable new command. |
| ReadingAnnotationTagRecord — `R/ReadingAnnotationTagRecord.swift` | change:ReadingAnnotationTagChange, writer:ID, operationID:ID, provenance:authenticated/legacy/imported, importedBy:ID?, importOperationID:ID?. |
| ReadingAnnotationTagDecision — `R/ReadingAnnotationTagDecision.swift` | threadID:ID, tag:Text, reference:{id:ID,digest:Digest}. |
| ReadingAnnotationSnapshot — `R/ReadingAnnotationSnapshot.swift` | version:Int, records:NoteRecord[], sources:Source[], diagnostics:Diagnostic[], tagHistory:TagRecord[], tagDecisions:TagDecision[]. Version1 lacks tags, v4 adds Reader metadata, v5 Readwise excerpts; decoder supports 1…5 and validates feature/version correspondence. |
| ReadingAnnotationRestore — same | records:NoteRecord[], sources:SealedSource[], diagnostics:Diagnostic[], expect:Rev?, digest:Digest, tagHistory:TagRecord[], tagDecisions:TagDecision[]. This sealed form is the `annotation.restore` archive, not the portable snapshot form. |
| ReadingHighlightReviewRecord — `R/ReadingHighlightReviewRecord.swift` | change:ReadingHighlightReviewChange, evidence:NoteRecord?, sourceLibraryID:ID, writer:ID, operationID:ID, importedBy:ID?, importOperationID:ID?. Evidence trust is reviewerAssertion vs importedClaim, derived from provenance. |
| ReadingHighlightReviewSnapshot — `R/ReadingHighlightReviewSnapshot.swift` | format:colophon.highlight-review, version:1, sourceLibraryID:ID, sourceEnabled:Bool, sourceSettings:[{libraryID:ID,enabled:Bool}], history:ReviewRecord[], exclusionDecisions,choiceDecisions:[{threadID:ID,reference:{id,digest}}], decisionGroups:ID[][]. |

Tags are inclusion/removal **decisions**, not a union of every historical tag. The graph validates
every target and exact chosen reference; live tag events must occur after thread creation and
before deletion. Review decision groups preserve imported ordering; choice/exclusion indexes
must equal the values derived from that history. Undo does not remove an event from history.
`ReadingHighlightReviewSnapshot` caps metadata/history via its validator and the separate
`ReadingHighlightReviewAdmissionLimits` accounting; keeping only the current queue loses
undo and provenance. Annotation sources may remain inaccessible while their descriptors survive.

## Answer, connection and custody records

| Model / source | Stored fields |
| --- | --- |
| ReadingQuestionReference — `R/ReadingQuestionReference.swift` | libraryID:ID, id:UUID, digest:Digest. Digest binds referenced content, not just UUID. |
| ReadingQuestionEvidence — `R/ReadingQuestionEvidence.swift` | source:NoteSource, anchor:NoteAnchor, note:NoteRef?, title:Text, kind:originalRange/retainedQuote. Text range or unresolved quote only; page/item anchors are not answer excerpts. |
| ReadingQuestionEvidence.Closure — same | sources:ReadingAnnotationSnapshot.Source[], notes:NoteRecord[]. Portable plaintext evidence graph. |
| ReadingQuestionEvidenceCustody — `R/ReadingQuestionEvidenceCustody.swift` | sources:ReadingAnnotationSealedSource[], notes:NoteRecord[]. Sealed exact evidence references in each prepared packet; no extra unreferenced sources or missing ancestor note records. |
| PreparedReadingAnswerKeep — `R/PreparedReadingAnswerKeep.swift` | answer:ReadingAnswer, custody:ReadingQuestionEvidenceCustody. |
| PreparedReadingQuestionChange — `R/PreparedReadingQuestionChange.swift` | value:visibility(ReadingAnswerVisibility) or connection(ReadingConnectionRevision), custody:ReadingQuestionEvidenceCustody. The nested variant must match operation kind. |
| PreparedReadingQuestionRestore — `R/PreparedReadingQuestionRestore.swift` | metadata:ReadingQuestionRecordMetadata, sourceLibraryID:ID, answers:ReadingAnswer[], visibility:ReadingAnswerVisibility[], visibilityGroups:QuestionRef[][], connections:ReadingConnectionRevision[], sourceDigest:Digest, custody:ReadingQuestionEvidenceCustody. |
| ReadingAnswerSnapshot — `R/ReadingAnswerSnapshot.swift` | format:colophon.reading.answers, version:Int, sourceLibraryID:ID, answers:ReadingAnswer[], visibility:ReadingAnswerVisibility[], visibilityGroups:QuestionRef[][], visibilityHeads:[{answer:QuestionRef,heads:QuestionRef[]}], evidence:Closure. |
| ReadingConnectionSnapshot — `R/ReadingConnectionSnapshot.swift` | format:colophon.reading.connections, version:Int, sourceLibraryID:ID, revisions:ReadingConnectionRevision[], heads:[{root:QuestionRef,heads:QuestionRef[]}], evidence:Closure. |

ReadingAnswer's `claims` use `ContextClaim={text:Text,citations:[{source:Int,quote:Text}]}`
from `C/ContextAnswers.swift`; source is an index into selected evidence. This differs from
podcast TranscriptAnswerClaim's exact Anchor objects. ReadingAnswer validation in
`R/ReadingAnswer.swift` permits 1…8 evidence items,≤6 claims and≤8 citations per claim;
the question scope validates a 1…500-character question and≤3,600 total excerpt characters.
Engine/runtime/prompt labels and exact citation quotations are validated separately. The 0.2 command normalizes to
typed evidence references after validating the old source claim and preserving exact originals.
`R/ReadingQuestionAdmission.swift`, `ReadingQuestionCustodyReceipt.swift`,
`ReadingQuestionReceiptLedger.swift`, `ReadingQuestionProjection.swift`,
`ReadingQuestionVisibilityGroups.swift` bind prepared metadata to actual signer/library,
retain request-body receipts, defer dependencies, validate visibility grouping and count
admission/storage budgets. Restore bypasses neither custody nor provenance validation.

## Browser ingress and source-only boundaries

`apps/suite/LaterSafariExtension/SafariWebExtensionHandler.swift` receives checkpoint/activity
messages, validates bounded data and writes destination-bound App Group inbox records. It
does not acquire library signing authority or perform a domain write. It handles reconcile
against bounded local SafariReadingStatus and local translation requests too.
`apps/suite/Later/SafariReadingController.swift` is a foreground inbox consumer: after checking
membership and publishing the destination route, it imports pending checkpoint/activity
through the typed service, refreshes session state and publishes status using
`apps/suite/Later/LaterSafariBridge.swift`. This is a foreground/background-ingress boundary,
not a render-time command path.

Safari request validation additionally caps passages at 4,096 and notes at 256; passage/note
IDs≤160 UTF-8 bytes/no controls; passage text≤256 KiB; note text≤64 KiB; kinds are paragraph,
heading, quote, list, code, image, caption. Source URL normalization preserves case-sensitive
path/query and removes fragment/default port; do not substitute broad canonical-URL dedup.

MagazinePublication is the committed enum `atlantic|wired` in `C/MagazinePublication.swift`.
Subscription metadata cannot grant paywall access; web cookies/authentication stay local.
Source.native capsules (`R/ReadingNativeSourceCapsules.swift`) have their own namespace and
key scope. Missing access is a visible migration gap, not permission to copy unrelated data.
