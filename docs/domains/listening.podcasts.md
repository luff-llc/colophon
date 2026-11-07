# listening.podcasts

Proposed 0.2 port; [README](README.md) defines shared types, provenance and query bounds.
Source prefix `L` is `packages/Colophon/Sources/ColophonListening/`; `T` is `apps/suite/Taupe/`.
There are **29 kinds in Podcasts.kinds**, plus four service-only kinds not advertised there.
The service projections must be migrated too; `Listening` alone is insufficient.

## 0.1 ordinary operations

Sources: `L/Podcasts.swift`, `Podcasts+Spec.swift`, `Podcasts+Content.swift`,
`Podcasts+Chapters.swift`, `Podcasts+Playlists.swift`, `Listening.swift`.
OperationSpec checks types/enums for tool writers; most older Listening cases do not check
v or repeat those checks. Unknown kinds remain in the log. `BlobRef` is
`{digest:Text,plain:Text,epoch:Int,size:Int}`; source-specific services validate it more strictly.

| Kind | Payload | Fold, validation and conflicts |
| --- | --- | --- |
| `show.follow` | `show:ID,feed:Text,title:Text` | Fold requires show/feed, defaults title to feed; creates or reactivates. Existing feed/title retained. Applies saved show speed. Writes signer-qualified show revision. |
| `show.unfollow` | `show:ID` | Sets following=false if known; records show revision even before a show exists, blocking baseline resurrection. |
| `show.settings` | `show:ID,speed:Number?,skipIntro:Number?,skipOutro:Number?` | Existing show; patch supplied numbers. No numeric bounds here. Speed also updates scoped preferences and revision, unless operation ID ambiguous. |
| `episode.setState` | `episode:ID,show:ID,consumption:Text,expect:Rev?` | Creates episode if needed; stale non-null state expectation adds conflict ID; otherwise sets consumption/stateRevision/updated. Writer enum notStarted/inProgress/doneEnough/completed/abandoned, fold accepts any string. |
| `episode.position` | `episode:ID,show:ID,seconds:Number,duration:Number?,deliberate:Bool,expect:Rev?` | Builder clamps seconds≥0, fold only requires number. Applies if deliberate, current position expectation matches, position advances, or current head is imported baseline. Updates position head, optional duration and claimed updated date. It is **not** a session. |
| `position.recover` | `episode,show:ID,seconds:Number,duration:Number\|null,expectedPosition:Rev\|null,expectedState:Rev\|null,inProgress:Bool` | Exact keys, v1; IDs nonblank≤256 bytes/no controls, finite nonnegative seconds/duration, revisions valid. Both heads and existing show must match. Atomically sets position and optionally inProgress. Otherwise no effect. |
| `queue.set` | `episodes:ID[],metadata:QueueMetadata[]?` | Array required; compactMap strings, duplicates allowed by old fold. Replaces order, updates qualified queue head, evicts metadata outside queue. Invalid optional metadata does not invalidate IDs. |
| `queue.retain` | `metadata:QueueMetadata[],expectedQueueRevision:Rev\|null` | v1, exact keys, exact queue head; only queued IDs; fills missing metadata, never changes order or existing descriptor. |
| `note.add` | `note,episode,show:ID,text:Text,seconds:Number?,quote:Text?,origin:person\|ai?,transcriptAnchor:Anchor?,captureThought:Object?` | Fold requires note/episode/text; first ID wins, missing show empty. Keeps creation signer/label, creationRevision, current editor, sequence/date. Origin defaults person and is a **self-claim**. Valid anchor quote overrides quote; malformed anchor still sets hasAnchorClaim. |
| `note.edit` | `note:ID,text:Text,expect:Rev?` | Stale string expectation appends text alternative; success sets text/revision/editor, keeps alternatives. |
| `note.resolve` | `note:ID,text:Text,expect:Rev?` | Same, but success clears alternatives. |
| `note.delete` | `note:ID` | Removes note, no tombstone; old same-ID recreation possible. |
| `episode.segments` | `episode,show:ID,audio:Text,source:detected\|person,detector:Text?,segments:[{start:Number,end:Number,kind:Text?}]` | Keyed episode/audio. Person set cannot be overwritten by non-person. Keeps elements with numeric end>start, kind defaults sponsor, sorts start; no digest/finite/nonnegative checks in this fold. Empty set can intentionally clear skips. |
| `episode.transcript` | `episode,show:ID,source:Text,language:Text?,blob:BlobRef,timed:Bool?,audio:Text?`; optional sourceReceipt/preparationID/preparationDigest | One selected record/episode. Timed outranks untimed, then person(3)>publisher(2)>other(1), equal rank latest wins. Valid 64 hex audio retained (case not forced); invalid audio becomes nil. Blob bytes not opened by fold. |
| `episode.chapters` | `episode,show:ID,audio:Text,source:Text,origin:Text?,entries:[{start:Number,title:Text}]` | Requires 64 hex audio and source; person protected from generated replacement. Filters finite nonnegative starts and nonblank titles, trims/truncates title to 160 characters, sorts start; empty valid list ignored. |
| `playlist.save` | `playlist:ID,name:Text,mode:manual\|automatic,allShows:Bool?,shows,episodes,excluded,pinned,included:ID[]?,order:newest\|oldest\|byShow?,includeFinished:Bool?,archived:Bool?,progress:any\|unplayed\|inProgress?,maxMinutes:Number?,titleContains:Text?,expect:Rev?` | Whole saved rule. Nonempty ID/name/mode; name trim+120 chars; arrays drop nonstrings/empty/duplicates, order defaults newest, booleans false, progress any. maxMinutes finite≥1 clipped to 1,440 then integer; title word trim+80 chars. Stale expect retains complete competing playlist; successful replacement discards old competing array. Rule results come from local feed catalogue. |

`showID = first32hex(SHA256(UTF8(feed)))`,
`episodeID = first32hex(SHA256(UTF8(feed + "\n" + guid)))`. No URL normalization is implied.
`QueueMetadata={episode,show,feed,guid,title,showTitle,audio:Text,duration:Number?,published:Number?}`
(`L/QueuedEpisodeMetadata.swift`): IDs must match derivation; credential-free HTTP(S) URLs≤4,096
bytes; GUID≤4,096, titles≤2,048; finite duration≥0/published; ≤512 unique descriptors, ≤16 KiB
each, ≤1 MiB batch. New queue builder rejects duplicate episode IDs even though old fold doesn't.

`Anchor={reference:{libraryID,episode,show,revision:Text,blob:BlobRef},startUTF16:Int,
lengthUTF16:Int,quote:Text}` (`L/TranscriptNoteAnchor.swift`, `SharedTranscript.swift`). Exact
source revision/blob/quote must be verified by `TranscriptNoteService`, not by display code.
Transcript blob: `{text:Text,words:[{text:Text,start:Number,end:Number,timing:Text?}]?}`.

## 0.1 atomic and legacy-publication kinds

These are app/device fenced; duplicate operation IDs are pre-scanned. A repeated ID makes
natural-end/import/source records ineligible and preference heads ambiguous. Receipts generally
use signer-scoped command/event IDs, not globally trusted caller strings. Qualified revisions
come from `PlaybackPreferenceBatch.revision`; do not parse them as raw operation IDs.

| Kind / source | Payload | Semantics |
| --- | --- | --- |
| `preferences.batch` — `L/PlaybackPreferenceBatchService.swift` | `commandID,commandDigest:Text,changes:{Text:Text},expected:{Text:Rev\|null}` | Exact keys, ≤15 nonempty changes, identical expected key set, ≤8,192-byte canonical body and matching digest. All heads match or entire batch stale. Receipt records applied/stale; same signer/ID different digest conflicts. |
| `playback.naturalEnd.batch` — `L/PlaybackNaturalEndBatchService.swift` | `libraryID:ID,events:EndEvent[],baseQueue:ID[],expectedQueueRevision:Rev\|null,seconds:Int,duration:Int,bodyDigest:Digest` | Exact keys/v1/library. 1…16 events, unique event/episode IDs, queue≤1,024, body≤65,536. Aggregate seconds/duration are ceiling sums for old caveats. All current queue/order/position/state heads must match pending events; atomically complete episodes and remove ended IDs/deduplicate queue. Record receipts even on stale. Changed event meaning poisons event ID; matching retry no-op. |
| `legacy.bridge.import` — `L/LegacyBridgeImportService.swift` | `bridgeVersion:1,crosswalkVersion:1,targetLibraryID,lineageID:ID,sourceRoot,crosswalkDigest,sharedInventoryDigest,commandDigest:Digest,parentSourceRoot:Digest\|null,expectedLineageRoot:Digest\|null,commandID:ID,feeds:FeedCrosswalk[],sharedOperationInventory:[{operationID:ID,digest:Digest}],expectedShowHeads:{ID:Rev\|null},sourceDescriptor:Descriptor?` | Bounded verified crosswalk (≤2,000 feeds,≤256 source operations,≤2 MiB). Digest/source lineage/show head checks; only fills missing show with no native head. A different root in same lineage quarantined, not incremental overwrite. Records reused/stale/conflict/applied receipts. Full old archive is local, not embedded. |
| `legacy.podcastState.import` — `L/LegacyPodcastStateImport.swift` | `version:1,libraryID,lineageID:ID,sourceRoot,digest:Digest,records:[{legacyID,feed,guid,rssLegacyID:Text,seconds:Number?,consumption:Text?,updated:Date}]` | ≤500 records/2 MiB; identities/digest validated; requires compatible accepted bridge root with no sourceDescriptor. Immutable per-source record digest; fills absent position/state heads only; imported baseline specially yields to native progress. |
| `podcast.source.publish` — `L/PodcastSourcePublication.swift` | `version:1,libraryID:ID,facts:SourceFact[],actions:SourceAction[],digest:Digest` | Validate complete batch before effects; immutable fact/action identities. Retain facts even when not applied. Baseline action only if head absent; live action exact head CAS. Actions affect follow/unfollow/position/consumption only. |

`EndEvent={eventID,episode,show,audio:Text,endSeconds:Number,actualDuration:Number,
expectedPosition:Rev|null,expectedState:Rev|null}`; duration>0≤604,800, end==duration, finite;
event IDs≤128 bytes, episode/show≤256, audio identity≤512. Audio identity is not always a digest.
`FeedCrosswalk={legacyID,feedURL,title,targetShowID:Text}`.
`Descriptor={format:opml-subscriptions-v1|overcast-all-data-v1,rawSourceDigest,semanticFactsRoot:Digest,
lineageSemantics:Text}`.
`SourceFact={actor,operationID:Text,clock:Int,date:Date,sourceDigest:Digest,kind:Text,
metadata:{itemID:Text,title?,feedID?,feedURL?,guid?,rssMemberIDs:Text[]?},body:JSON}`.
Kinds item/follow/unfollow/deleteItem have empty body; position uses seconds/fraction/deliberate/
passageAnchor; consumption uses consumption; playbackVisibility uses sessionID/hidden;
playbackEvidence uses sessionID/startSeconds/endSeconds/elapsed/audioDigest/started/ended/hidden?.
Those last two are retained **source claims**, not new native session observations.
`SourceAction={actionID,factKey,feed:Text,guid,rssMemberID,identityFactKey:Text|null,
mode:baseline|live,expect:Rev|null}`. Source mapping proves legacy RSS membership where needed;
unsupported/non-audio positions cannot become native playback positions.
Publication batches have ≤128 unique facts and ≤128 unique actions, at least one total,
and≤2 MiB canonical body. Actors/operation IDs/item IDs≤512 bytes, nonnegative source clocks,
finite dates; metadata/body keys are closed. Time spans are finite 0…604,800, fraction 0…1,
playback evidence ended≥started. Position facts require deliberate plus seconds or fraction;
consumption requires a recognized value. Action ID≤128 bytes, valid feed URL, digest fact keys
and bounded expected revision. Playback visibility is folded by original source clock/actor/
operation ID, not arrival in the new library.

Preference keys: global `playback.<field>`, show/episode scopes
`playback.show:<ID>.<field>` / `playback.episode:<ID>.<field>` and global `listening.<field>`.
Playback fields: speed, backward, forward, shortenSilence, levelSpeech, monoAudio, skipSponsors,
skipDetectedSponsors, skipAdChapters. Listening fields: doublePress, triplePress, carUsesChapters,
sentenceRewind, smartResume, markButton. Boolean strings true/false; scoped empty string means
inherit. Speeds are the discrete set in PlaybackPreferenceBatchService (0.75…3, not every real
number); skip intervals 5/10/15/30/45/60; doublePress=skipForward/nextChapter/mark;
triplePress=skipBack/sentence/undoSkipOrSentence/comment. IDs are parsed by known suffix, not dots.

## 0.1 service projections and log-only data

The following eight advertised and four unadvertised service kinds are **not folded by
Listening**. They are projected by their named services, which also inspect current access,
blob availability and sometimes host time. Preserve these records even if a simple state read
does not show them. `Cmd` below means required `commandID:Text,commandDigest:Digest` over the
canonical body without those two fields; duplicate signer/command with changed meaning conflicts.

| Kind | Payload / source | Validation and projection |
| --- | --- | --- |
| `answer.save` | `libraryID:ID,question:Text,claims:[{text:Text,citations:Anchor[]}],Cmd`; `L/TranscriptAnswerService.swift` | App/device/agent; question≤4,000 UTF-16 units,≤50 claims/200 citations/40k total claim units, each quote≤8k and lengthUTF16 equals quote length, nonempty claims/citations, validated exact sources; verified/pendingSource/invalidCitation/conflict. Does not create note automatically. |
| `transcript.prepare` | `request:PreparationRequest,audio:BlobRef,worker:ID`; `L/TranscriptPreparationService.swift` | App/device request, selected agent worker; matching library, policy=mac, no audioURL, language nonempty, digest matches audio.plain, 0<size≤2 GB. Same requester/request ID different body conflicts. |
| `transcript.prepare.cancel` | `requestRevision:Rev`; same source | Only original requester; cancellation durable. |
| `transcript.prepare.result` | `requestRevision:Rev,result:BlobRef`; same source | Selected currently authorized worker; multiple different plaintext results held. Result must match recording/language/complete receipt; requester separately writes episode.transcript to install it. |
| `question.request` | `libraryID,question,targetAgentID,scope:Anchor[],expires:Number,Cmd`; `L/TranscriptQuestionService.swift` | App/device; 1…20 distinct passages,≤20k UTF-16 total, each quote≤8k, question≤4k. Host checks deadline in future≤7 days and≤32 pending per requester; current source/access required. |
| `question.response` | `libraryID,requestRevision,scopeDigest:Digest,claims:Claim[],Cmd`; same source | Only selected agent; citations exact subset of scope,≤50 claims/200 citations/40k claim UTF-16. More than one response produces conflict. |
| `question.cancel` | `libraryID,requestRevision,Cmd`; same source | Any currently enrolled app/device can cancel; no automatic reassignment. |
| `question.admit` | `libraryID,requestRevision,responseRevision,Cmd`; same source | Receiving app/device verifies unique response, current source/access and its own clock before expiry. Existing admitted answers remain durable after expiry; agent dates cannot authorize late response. |
| `capture.response` (unadvertised) | `requestID,requestRevision,text,Cmd`; `L/CaptureThoughtService.swift` | Selected agent responds once to exact original thought request; text≤10k UTF-16; source must be ready; conflicts/cancellation retained. |
| `capture.cancel` (unadvertised) | `requestID,requestRevision`; same source | Original requester app cancels; no note text overwrite. |
| `context.propose` (unadvertised) | `reference:SharedTranscriptReference,contributionID,text,citation:Text,expectedRevision:Rev\|null,Cmd`; `L/SharedTranscriptService.swift` | Agent only; exact reference, quote in verified transcript; contribution owned by original proposer. Missing source defers, wrong quote invalid, stale head receipt. |
| `context.accept` (unadvertised) | `reference,contributionID,proposalRevision,expectedRevision:Rev\|null,note:Text\|null,Cmd`; same source | App/device only; exact current proposal once, preserves proposal and acceptance attribution separately. |

`PreparationRequest` (`L/TranscriptPreparation.swift`) contains required id/libraryID/episode/show,
policy:publisherThenSpeech|speech|manualImport|mac, holdAudio:Bool; optional audioURL,
recordingSource, recordingDigest, language, feed, enclosure, title, workerID. Only mac requests
are shared by this service. `captureThought` is an extension on note.add:
`{requestID,digest,surroundingText,originalText:Text|null,voice:BlobRef|null,
voicePlain:Digest|null,voiceMimeType:Text|null,targetAgentID:ID|null}`. Surrounding text≤2k UTF-16,
thought≤10k, voice≤6 MiB. Original note text remains original; responses are separate.

Note rows and details carry `created`, the signer's claimed date of the `addNote` operation (wall-clock display; order stays logical). Derived: following sorted by title; episode fraction capped to 1; note time/sequence order;
active playlists; transcript rank; skip/chapter lookups by recording; latest episode state
history. `L/SeekHistory.swift`, `PlaybackProgressJournal.swift`, `PlaybackAudioOwnership.swift`,
`TranscriptPreparationJournal.swift` are device-local recovery/ownership, not extra shared opcodes.
`L/TranscriptRecordingSource.swift` defines optional request/receipt recordingSource as
`{feed,guid,enclosure:Text,byteLength:Int64}`. Source receipts in
`L/TranscriptPreparation.swift` retain `retrieved:Date,completeness:complete|partial|unknown`
and optional sourceURL/finalURL/raw:BlobRef/mediaType/etag/lastModified/parser/engine/runtime/
language/recordingSource/recordingDigest. These are durable source observations; the original
worker job journal and progress percentage are local.

## App inventory and hot paths

| Surface / source | Writes | Reads / heat |
| --- | --- | --- |
| `T/Model/AppModel.swift`, `ListenLibrary.swift`, `TaupePlaybackSettingsBridge.swift`, `T/Shows/ShowListeningSettings.swift` | follow/unfollow/settings/preferences.batch; queue.set/retain | Listening once on reload; shows, episodes, queue/progress from caches per render. Feed reload/enrichment background. |
| `T/Model/AppModel+Playlists.swift`, `T/Library/TaupePlaylistsView.swift` | playlist.save | Rule + local feed catalogue + per-episode progress, per revision/filter; visible rows during scroll. |
| `T/Player/ListenPlayer.swift` | episode.position/setState, position.recover, naturalEnd.batch, note.add | Position/queue/preferences at playback start, save, seek/end and recovery. AVPlayer observer every .5s; enhancements observer .1s. Passive journal writes throttled by passiveInterval; ticks must not refold. |
| `T/Library/PlaybackHistoryView.swift` | State changes through player/model | Memoized latest episode states grouped by claimed date; per revision/calendar/day/filter, plain row lookups on scroll. `PodcastSourceHistoryView.swift` and `LegacySourceHistoryView.swift` show separately imported history. |
| `T/AdSkip/AdSkipper.swift`, `T/Model/AppModel+Chapters.swift`, `T/Player/PlayerChaptersNotesPage.swift` | episode.segments/chapters | Recording-specific intervals/chapters; cached binary/time lookup during ticks, list on presentation. Person edits are user actions; detection background. |
| `T/Transcripts/TranscriptStore.swift`, `TranscriptPreparationCoordinator.swift`, `TranscriptPage.swift`, `TranscriptCaptureLookup.swift` | transcript, preparation request/cancel/result via typed services | Selected record by episode on revision; blob decoded/indexed once; visible passages per scroll and active segment per tick. Transcript search on request, never full corpus FFI copy. |
| `T/Ask/AskAnswerPersistence.swift`, `T/Search/SearchQuestionBroker.swift`, `SearchRetrieval.swift` | answer.save, question.request/cancel/admit; note.add to intentionally keep a result | Bounded retrieval, job/answer status, exact anchors on action/background response. Agent response originates outside native UI. |
| `T/Capture/CaptureThoughtSheet.swift`, `CaptureThoughtIntent.swift`, `T/Notes/NoteSourceReview.swift`, `T/Player/TimestampMarkOutbox.swift` | note.add with captureThought; response/cancel via service; note edits through note UI | Original/response/anchor details on action, durable local retry outbox. NewPodcastNoteIntent, ListenIntents and SkipListeningChapterIntent route actions to player. |
| `T/Notes/NoteEditor.swift`, `AllNotesView.swift`, `EpisodeNotesSection.swift` | note.edit/resolve/delete | Exact note/text revision and alternatives in editor; cached note summaries per render/scroll, writes on save/delete/resolve. |
| `T/Player/NowPlayingWidgetPublisher.swift`, `WidgetPlaybackActionCoordinator.swift`; `apps/suite/TaupeWidgets/Shared/NowPlayingControlIntents.swift`, `NowPlayingSnapshot.swift`, `RackWidgetSnapshot.swift` | Widget intent dispatch to player, then position/state/note writes there | Bounded local snapshots at publication; widget render reads snapshot, not replica. Controls/foreground recovery must recheck destination and current revision. |
| `T/Player/PhoneWatchRemote.swift`, `TaupeCarPlaySceneDelegate.swift`; `T/Spatial/TaupeSpatialKeep.swift`, `TaupeSpatialMoment.swift` | Remote seek/mark/queue through player; spatial note.add | Watch queue prefix 20; CarPlay show/queue rows on refresh; spatial exact note/source on open. Tick display from local values. |
| `apps/suite/Shared/Transcripts/SharedTranscriptAccess.swift`, `SharedTranscriptReader.swift`, `SharedTranscriptLibraryView.swift` | Context acceptance through service; cross-app continuation | Exact transcript and notes in Later/Scribenda; library listing on revision, detail on open. |
| Legacy `apps/apple/App/Sync/PodcastLibraryPublisher.swift`, `PodcastLibraryConnection.swift`, `PodcastSharedPresentation.swift` | podcast.source.publish from old journal; baseline/live actions | Serial background source extraction; shared state/presentation on connection and revision. This is the direct legacy→Colophon bridge. |
| Android `android/app/src/main/kotlin/xyz/marginalia/android/audio/PlaybackService.kt`, `PlaybackController.kt`, `PlayerScreen.kt`, `ListeningHistoryPanel.kt`, `PodcastPlaylistsPanel.kt`, `AppModel.kt` | Older journal author position/consumption/playbackEvidence/preferences, not these signed kinds | Service playback ticks, Compose visible playback/list/history. Port `android/core-journal/src/main/kotlin/xyz/marginalia/journal/PlaybackEvidence.kt`, `PodcastPlaylists.kt`, `PlaybackPreferences.kt` through separate source adapter. |

Service-only remote producers also include
`packages/Colophon/Sources/colophon/SharedTranscriptCommand.swift` (context proposal/acceptance),
`TranscriptQuestionCommand.swift` (scoped request/response/admission) and
`packages/Colophon/Sources/taupe-transcript-worker/main.swift` (preparation results).
These run on command/background boundaries, not UI render paths. Generic module adapters
advertise only their operation specs; a kind's presence in history does not imply it is a
generic tool or that the current app has a button for it.

## Proposed 0.2 commands and reducer

Thirty clean kinds, all v1. Common validation: finite nonnegative seconds, positive finite
duration when supplied, bound strings/arrays before allocation, lowercase digests, proper
URLs for new descriptors; old malformed values retained as evidence. State enum is closed for
new commands. Role-sensitive actions use authenticated member kind, never source="person"
alone. New note text≤256 KiB; inline transcript bytes are forbidden. Segment/chapter lists≤2,048;
chapter titles≤160 characters. Queries below expose status when evidence bytes are unavailable.

| Kind | Payload | Effect/conflict rule |
| --- | --- | --- |
| `follow` | `id,url,title` | Create/reactivate show; metadata patch only when explicitly supplied, ordered show head. |
| `unfollow` | `id;expect:Rev?` | Reversible follow flag, retain pre-creation unfollow head. |
| `editShow` | `id;title:Text?,skipIntro:Number?,skipOutro:Number?,expect:Rev?` | Show settings CAS, skips≥0. Speed uses preference command. |
| `setPreferences` | `id:ID,changes:[{scope:global\|show\|episode,target:ID?,field:Text,value:Bool\|Number\|Text\|null,expect:Rev\|null}]` | ≤15 atomic per-key head comparisons; same allowed fields/discrete values as old typed helper; null=scoped inheritance; receipt by signer/id. |
| `setState` | `id,show,consumption;expect:Rev?` | Episode state CAS, distinct from position. |
| `position` | `id,show,seconds;duration:Number?,seek:Bool=false,expect:Rev?` | Deliberate seek applies backwards; otherwise matching head or forward progress. Never a session log. |
| `recoverPosition` | `id,show,seconds,expectedPosition:Rev\|null,expectedState:Rev\|null,inProgress:Bool;duration:Number?` | Atomic exact heads; crash recovery only. |
| `queue` | `episodes:ID[];expect:Rev?,metadata:EpisodeDescriptor[]?` | Unique IDs≤1,024; replace order by queue CAS, retain descriptors separately. |
| `episode` | `id,show;feed,guid,title,showTitle,audioURL:Text?,duration:Number?,published:Instant?,transcriptExcerpt:Text?` | Add/patch descriptive catalogue state; no position/queue changes. Imported retained metadata outranks transient cache only as a retained source claim. |
| `completePlayback` | `id:ID,events:EndEvent[],baseQueue:ID[],expect:Rev\|null` | ≤16 events; compare all position/state/queue heads atomically; complete and remove queued IDs; receipt prevents retries. Drop old ceiling-budget fields. |
| `addNote` | `id,episode,show,text;seconds:Number?,quote:Text?,anchor:Anchor?,capture:Capture?` | Immutable occurrence/parent; creation attribution separate from latest text editor. Capture descriptor retains original voice/text. |
| `editNote` | `id,text;expect:Rev?` | Text CAS and full alternatives. |
| `resolveNote` | `id,text,expect:Rev,resolves:Rev[]` | Explicit reviewed alternatives. |
| `deleteNote` | `id;expect:Rev?` | Tombstone, preserve late edits. |
| `setSegments` | `episode,show,recording:Digest,source:detected\|person,segments:[{start,end:Number,kind:Text}];detector:Text?,expect:Rev?` | Per-recording CAS; validate all entries (no partial filtering); authenticated person review outranks detection; empty clears. |
| `saveTranscript` | `id,episode,show,blob:Blob,source:Text,timed:Bool;language:Text?,recording:Digest?,receipt:JSON?` | Retain all immutable versions; selection rank timed/person/publisher/other then fold order. Source assertions don't change authenticated origin. |
| `setChapters` | `episode,show,recording:Digest,source:Text,entries:[{start:Number,title:Text}];origin:Text?,expect:Rev?` | Per-recording CAS, person protection; nonempty valid sorted entries. `origin` is a provenance self-claim (≤128, e.g. `id3`), stored and returned as `contentOrigin`; row `origin` stays the authenticated person/ai attribution. |
| `savePlaylist` | `id,name,mode;allShows,includeFinished,archived:Bool=false;shows,episodes,excluded,pinned,included:ID[]=[];order=newest,progress=any,maxMinutes:Int?,titleContains:Text?,expect:Rev?` | Whole rule,≤1,024 IDs per array, preserve full alternatives; local feed resolution never writes rule membership. |
| `saveAnswer` | `id,question,claims:Claim[]` | Immutable cited answer; old bounded claims rules; exact source refs, byte verification remains host-derived. |
| `requestTranscript` | `id,episode,show,worker:ID,audio:Blob,recording:Digest,language:Text` | App/device, immutable delegated request; no network URL authority or automatic execution from import. |
| `cancelTranscript` | `id,request:Rev` | Requester-only durable cancel. |
| `supplyTranscript` | `id,request:Rev,result:Blob` | Selected agent only; conflicting plaintext results remain alternatives; never auto-select transcript. |
| `askQuestion` | `id,question,scope:Anchor[],worker:ID,expires:Instant` | App/device; bounded exact scope; host enforces current access/deadline. |
| `answerQuestion` | `id,request:Rev,scopeDigest:Digest,claims:Claim[]` | Selected agent, exact scope, no implicit acceptance. |
| `cancelQuestion` | `id,request:Rev` | App/device cancellation. |
| `acceptAnswer` | `id,request:Rev,response:Rev` | App/device technical admission receipt after verification; preserved separately from person endorsement. |
| `respondCapture` | `id,request:Rev,text` | Selected agent, one immutable response/alternatives; original note stays intact. |
| `cancelCapture` | `id,request:Rev` | Original requester cancellation. |
| `proposeContext` | `id,reference,contributionID,text,citation;expect:Rev?` | Agent, owns contribution, exact cited source and head. |
| `acceptContext` | `id,reference,contributionID,proposal:Rev;note:Text?,expect:Rev?` | App/device, exact pending proposal, separate acceptance attribution. |

`EpisodeDescriptor` has the old QueueMetadata semantic fields renamed audio→audioURL and
published→Instant. `EndEvent` keeps eventID/episode/show/audio/endSeconds/actualDuration and
expectedPosition/expectedState; payload id supplies batch receipt identity. `Capture` keeps
requestID, originalText, voice:Blob?, voiceMimeType?, surroundingText, targetAgentID?; integrity
comes from the operation and blob digests. New request references are operation IDs. Anchor
references use new immutable transcript ID/revision and Blob rather than ciphertext identity.

Separate state indexes: shows, episode metadata, state/position heads, queue order/head,
preferences/heads/receipts, notes/tombstones, recording content, transcript versions/selection,
playlists, answers/jobs/context contributions. Import evidence and source session facts have
their own bounded read index. Duplicate IDs from invalid old libraries must never become
ambiguous new authenticated revisions. Unknown properties survive in extensions.

Reducer computes deterministic structural job state. Current access, expiry-at-now, source
availability and citation verification are host overlays with explicit statuses; no host clock
or I/O inside apply. Old jobs must not resume merely because they were imported. Download
availability, device speed overrides, transient sleep timers, audio ownership, seek undo,
progress outboxes, speech engine state, transcript layouts/search indexes and network feed
caches remain local. Shared personal preference choices and retained transcript/audio originals
remain shared descriptors/blobs. Never substitute a cached URL for pinned recording identity.

## Named queries (19)

`EpisodeRow={id,show,title?,showTitle?,seconds,duration?,consumption?,updated?,positionRevision?,
stateRevision?,metadataAvailable:Bool,transcriptAvailable:Bool,noteCount:Int}`; availability here
means a retained descriptor, with host byte status separate. Page and Attributed follow README.

| Query(arguments) | Result value / order | Path |
| --- | --- | --- |
| `shows(following:Bool=true,cursor?,limit?)` | Page `{id,title,url,following,revision}`, title/ID | Shows/grid |
| `show(id)` | `{show:Attributed,skipIntro?,skipOutro?,episodeCount}` | Show settings |
| `episodes(show?:ID,state?:Text,cursor?,limit?)` | Page EpisodeRow, publication/order key then ID | Show/library rows; host combines transient public feed catalogue outside shared reducer |
| `episode(id)` | `{row:EpisodeRow,metadata:EpisodeDescriptor?,heads,extensions}` | Player/detail |
| `queue(cursor?,limit?=20)` | `{head:Rev?,page:Page<EpisodeRow>}` in explicit order | Up Next, watch, CarPlay |
| `playbackContext(episode,recording?:Digest)` | `{episode:EpisodeRow,queueHead,next:EpisodeRow?,preferences:{field:JSON},preferenceHeads,segmentHead?,chapterHead?,transcriptID?}` | Once at play/revision, never whole Listening per tick |
| `playlists(archived:Bool=false,cursor?,limit?)` | Page `{id,name,mode,revision,alternativeCount}` | Playlist list |
| `playlist(id)` | `{rule:JSON,revision,alternativeCount,extensions}` | Rule editing; evaluate public feed results in host index with its own pagination |
| `notes(episode?:ID,cursor?,limit?)` | Page `{id,episode,seconds?,textPreview,quotePreview?,revision,creationRevision,authorLabel,origin,anchorClaimed,alternativeCount}`; seconds/order/ID within episode, creation descending globally | Notes/mark history |
| `note(id)` | `{note:Attributed,text,quote?,anchor?,capture?,creationRevision,lastTextEditor,alternativeCount}` | Editor/source review |
| `recordingContent(episode,recording,kind:segments\|chapters,cursor?,limit?)` | Page segment/chapter descriptors plus `{head,source,contentOrigin?}`; start then stable ID | Page initially, local active-time lookup per tick |
| `recordings(episode?,kind?:segments\|chapters,cursor?,limit?)` | Page `{episode,show,recording,kind,head,source,contentOrigin?,personReviewed,count}`; recording key order | Which recordings carry chapters/segments, without their entries |
| `preferences(scope?:global\|show\|episode,target?,cursor?,limit?)` | Page `{key,scope,target?,field,value,revision,author,authorLabel,origin}`; key order | Settings screens: current heads to pass as `expect` in `setPreferences` |
| `transcripts(episode?:ID,cursor?,limit?)` | Page `{id,episode,blob,source,timed,recording?,language?,selected,revision}` | Transcript library/detail; blob/chunk text from host |
| `history(mode:latestEpisode\|importedSession,finishedOnly:Bool=false,cursor?,limit?)` | Page EpisodeRow. `importedSession` lists episodes whose position or state is an authenticated imported baseline, with `positionBaseline`/`stateBaseline` flags; claimed activity date then ID | History, clearly distinct modes |
| `jobs(kind:transcript\|question\|capture,episode?:ID,status?:Text,cursor?,limit?=20)` | Page `{id,kind,requestRevision,worker?,status,responseRevision?,sourceRefs,deadline?}` | Background broker/status |
| `contributions(kind:answer\|context,id?:ID,episode?:ID,cursor?,limit?=20)` | Page `{id,textPreview?,question?,claims?,reference?,proposalRevision?,acceptanceRevision?,author,origin,sourceStatus}`; id requests full bounded record | Answers/context review |
| `listeningCounts(show?:ID)` | `{followed,episodes,inProgress,finished,queued,notes,transcripts,pendingJobs,conflicts}` | Sidebar/badges |
| `conflicts(object:ID,cursor?,limit?)` | Page complete attributed candidates/receipts `{component,expected,found,outcome,candidate,historical}` | Recovery and explicit reconciliation |

Transcript `moment`, passage paging and full-text search are **host blob-index APIs**, not
pure reducer queries: `passages(transcript,startUTF16,limit≤100)`,
`moment(transcript,seconds,before≤300,after≤10)` and
`searchTranscripts(query,cursor,limit≤25)` return bounded source-pinned snippets and offsets.
Rebuild index by plaintext digest; no whole blob loading on each tick/scroll. These APIs require
the namespace's current read access and report missing/invalid bytes distinctly.

## Every-kind import mapping

Use the README history/evidence manifest for every row. All old role/origin claims remain
historical attribution; importer signs clean effects. Preserve all transcript candidates and
invalid anchors, not just the old selected record. Map operation references through typed
component maps and source references through digest-preserving blob resealing.

| 0.1 kind | 0.2 operation(s) / disposition |
| --- | --- |
| `show.follow` | `follow`, preserving first stored title/feed and whether reactivation was effective. |
| `show.unfollow` | `unfollow`, including pre-creation unfollow marker. |
| `show.settings` | `editShow` for skips plus `setPreferences` for accepted speed; invalid old values evidence-only. |
| `preferences.batch` | `setPreferences` for applied batches; keep stale/conflicted/duplicate receipts in evidence; map each head, convert string values/inheritance. |
| `episode.setState` | `setState`; stale/unknown consumption stays evidence. |
| `episode.position` | `position`, deliberate→seek; reproduce only effective reports. Preserve rejected passive reports in evidence. |
| `position.recover` | `recoverPosition` with both mapped heads only if originally effective; stale recovery evidence retained. |
| `queue.set` | `queue`, collapse duplicate IDs preserving first occurrence for new unique queue, record original duplicate order in evidence. Valid metadata→episode descriptors; malformed optional metadata never drops queue order. |
| `queue.retain` | `episode` descriptors for actually retained missing metadata; preserve expected old queue head and receipt in provenance. No queue mutation. |
| `playback.naturalEnd.batch` | `completePlayback` for applied pending events; carry event identities/receipts, map exact heads. Old seconds/duration ceiling fields retained only in evidence: 0.2 has grant writeBudget, not these caveats. |
| `note.add` | `addNote`; note ID lifecycle map, pinned anchor map and capture descriptor; malformed anchor remains explicitly unverified evidence. |
| `note.edit` | `editNote`; stale complete alternatives in evidence with original editor recovered. |
| `note.resolve` | `resolveNote` for effective resolution and exact translated alternatives; stale attempt remains evidence. |
| `note.delete` | `deleteNote`; later same-ID note.add gets distinct occurrence. |
| `episode.segments` | `setSegments` with the elements the old fold kept; invalid/unbounded entries and overridden sets preserved in evidence. Never mark detector claim as person review without authenticated provenance. |
| `episode.transcript` | `saveTranscript` for each valid retained candidate, preserving rank/recording/source receipts. Missing blob descriptor stays missing; it cannot be verified merely from timed=true. |
| `episode.chapters` | `setChapters` using old filtered/truncated values; preserve raw entries in evidence. |
| `playlist.save` | `savePlaylist` with explicit old defaults/normalized rule; competing and replaced competing versions remain evidence. No feed-derived episode expansion into shared history. |
| `legacy.bridge.import` | `follow` only for actually applied missing follows; retain roots, descriptors, inventory, applied/skipped/stale/conflict receipts in import evidence. No legacy opcode in Rust. |
| `legacy.podcastState.import` | Conditional baseline `position`/`setState` only for fields it supplied; retain source actor/record identity/digest and special baseline precedence in importer. Never claim listening sessions. |
| `podcast.source.publish` | Applied action→follow/unfollow/position/setState; all immutable source facts and source-action receipts retained in evidence. PlaybackEvidence/Visibility feed importedSession index only, never native sessions; item/deleteItem facts do not become arbitrary deletions. |
| `answer.save` | `saveAnswer` if references map; invalid/missing citations remain flagged evidence. |
| `transcript.prepare` | Historical request evidence; do not enqueue old worker identity. Completed artifacts import via saveTranscript. New delegation requires a newly enrolled worker and requestTranscript. |
| `transcript.prepare.cancel` | Historical cancellation evidence linked to request; no active job revived. |
| `transcript.prepare.result` | Retain result blob/receipt in evidence; only an old installed transcript becomes saveTranscript automatically. |
| `question.request` | Historical bounded question/scope evidence; no active request/expiry capability transferred. |
| `question.response` | Preserve attributed candidate; an admitted durable response may become saveAnswer with translated claims. Unadmitted response remains pending historical evidence. |
| `question.cancel` | Preserve terminal cancellation evidence. |
| `question.admit` | Preserve receipt and historical acceptance; saveAnswer for the accepted response once, never synthesize new agent authentication. |
| `capture.response` | Preserve response beside mapped capture request in evidence; a continued new live request uses respondCapture only after re-enrollment. Original note text unchanged. |
| `capture.cancel` | Retain historical cancelled status; original thought survives. |
| `context.propose` | Preserve immutable proposed contribution in evidence with exact transcript reference and source validation outcome; do not sign it as a new agent proposal. |
| `context.accept` | Preserve historical accepted contribution and both attributions through SDK contributions evidence overlay; do not impersonate original proposer/reviewer. |

Drop local download flags, player timers/ownership, pending retry work, decoded transcript and
feed caches from shared history. Keep original voice/transcript/audio evidence if referenced.
Private legacy archive files not referenced by readable operations cannot be reconstructed from
the shared library: report the missing source rather than fabricate bridge verification.

## Open questions

- The evidence overlay must support historical jobs/contributions/session facts as first-class
  SDK results, or a separate clean archival-record protocol is needed before release.
- Source ranking needs a product decision for unverified publisher/person assertions from
  imported data. This proposal preserves rank as a historical fact and new authenticated roles.
- Confirm limits and pagination for a >1,024-entry queue; import currently preserves overflow
  as evidence and reports it, rather than silently losing the tail.
- The 0.2 preview position command identifies an episode by id; confirm adding show and
  distinct state/position heads with existing consumers. Blob and host-index APIs need a
  shared binding contract. No playback timing benchmarks or real-library import were run.

## Legacy importer normalization

The importer normalizes shipping 0.1 payloads against the destination schema before validating a
child: an explicit `null` is dropped where the destination field does not accept null (heads such as
`expect: null` keep their meaning), and a numeric Unix-second `published` (episode and queue
descriptors) becomes an RFC 3339 UTC string. The original payload stays unchanged in evidence, so
host evaluators no longer patch these in `effectivePayload`.
