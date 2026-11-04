import ColophonAuthority
import ColophonCore
import ColophonReplica
import Foundation

/// The `listening.podcasts` projection.
public struct Listening: Sendable {
  public struct Show: Sendable, Identifiable, Hashable {
    public let id: String
    public var feed: String
    public var title: String
    public var following: Bool
    public var speed: Double?
    public var skipIntro: Double?
    public var skipOutro: Double?
  }

  public struct Episode: Sendable, Identifiable, Hashable {
    public let id: String
    public var show: String
    public var seconds: Double = 0
    public var duration: Double?
    public var positionRevision: String?
    public var consumption: String?
    public var stateRevision: String?
    public var updated: Date

    public var fraction: Double {
      guard let duration, duration > 0 else { return 0 }
      return min(1, seconds / duration)
    }
  }

  public struct Note: Sendable, Identifiable, Hashable {
    public let id: String
    public let episode: String
    public let show: String
    public let seconds: Double?
    public var text: String
    public let quote: String?
    /// `person` or `ai`.
    public let origin: String
    /// Verified operation signer, independent of the self-declared legacy `origin`.
    public let authorID: String
    public let author: String
    /// Immutable signed note.add revision, even after a later edit changes `revision`.
    public let creationRevision: String
    /// Signer of the text currently shown; stale alternative edits do not replace it.
    public var lastTextEditorID: String
    public var lastTextEditorLabel: String
    public let anchor: TranscriptNoteAnchor?
    /// A present but malformed signed claim is not a legacy note.
    public let hasAnchorClaim: Bool
    public let sequence: Int
    public var revision: String
    public var alternatives: [String] = []
    /// When the note was made, from the operation that added it.
    public var created: Date = .distantPast
  }

  public struct Segment: Sendable, Hashable {
    public let start: Double
    public let end: Double
    public let kind: String
  }

  public struct SegmentSet: Sendable, Hashable {
    public let audio: String
    public let segments: [Segment]
    /// `person` or `detected`.
    public let source: String
    public let detector: String?
    public let by: String
  }

  public struct TranscriptRecord: Sendable, Hashable {
    public let source: String
    public let language: String?
    public let blob: BlobRef
    public let timed: Bool
    public let by: String
    /// The recording it was made from (lowercase hex SHA-256), when made from audio.
    public var audio: String? = nil
  }

  public private(set) var shows: [String: Show] = [:]
  public private(set) var episodes: [String: Episode] = [:]
  public private(set) var queue: [String] = []
  /// Revision of the last IDs-changing operation, including an older client's IDs-only write.
  public private(set) var queueRevision: String?
  public private(set) var queuedEpisodeMetadata: [String: QueuedEpisodeMetadata] = [:]
  /// Admitted preference values. Scoped empty strings are retained as explicit inheritance.
  public private(set) var preferences: [String: String] = [:]
  public private(set) var preferenceRevisionByKey: [String: String] = [:]
  public private(set) var preferenceReceipts: [String: PlaybackPreferenceBatchReceipt] = [:]
  public private(set) var preferenceCommandConflicts: Set<String> = []
  /// A repeated signed operation ID cannot serve as an unambiguous preference revision.
  public private(set) var preferenceIntegrityConflicts: Set<String> = []
  /// Each natural end has a signer-scoped receipt independent of its batch operation.
  public private(set) var naturalEndReceipts: [String: PlaybackNaturalEndReceipt] = [:]
  public private(set) var naturalEndEventConflicts: Set<String> = []
  public private(set) var naturalEndIntegrityConflicts: Set<String> = []
  /// Signed, provisional feed-crosswalk imports. These attest mapped podcast semantics only;
  /// the complete Marginalia archive is retained separately on the importing device.
  public private(set) var legacyBridgeReceipts: [String: LegacyBridgeImportReceipt] = [:]
  public private(set) var legacyBridgeRootReceipts: [String: LegacyBridgeImportReceipt] = [:]
  public private(set) var legacyBridgeLineageRoots: [String: String] = [:]
  public private(set) var legacyBridgeSourceOperationHashes: [String: [String: String]] = [:]
  public private(set) var legacyBridgeCommandConflicts: Set<String> = []
  public private(set) var legacyBridgeSourceRootConflicts: Set<String> = []
  public private(set) var legacyBridgeSourceRecordConflicts: Set<String> = []
  public private(set) var legacyBridgeIntegrityConflicts: Set<String> = []
  /// Importer attestations, separate from observed listening sessions. One immutable source
  /// record can supply missing baseline fields once; native state always takes precedence.
  public private(set) var legacyPodcastStateDigests: [String: String] = [:]
  public private(set) var legacyPodcastStateReceipts: Set<String> = []
  public private(set) var podcastSourceFacts: [String: PodcastSourceFact] = [:]
  public private(set) var podcastSourceActions: [String: PodcastSourceActionReceipt] = [:]
  public private(set) var podcastSourceRevisions: [String: PodcastSourceActionReceipt] = [:]
  public private(set) var podcastSourceReceipts: Set<String> = []
  public private(set) var podcastSourceConflicts: Set<String> = []
  private var importedPositionRevisions: Set<String> = []
  /// Last operation changing a show's existence or settings, including an imported first follow.
  public private(set) var showRevisions: [String: String] = [:]
  private let authenticatedLibraryID: String?
  public private(set) var conflicts: [String] = []
  public private(set) var notes: [String: Note] = [:]
  /// episode → audio identity → the segments in force for that audio.
  public private(set) var segments: [String: [String: SegmentSet]] = [:]
  /// episode → the transcript in force: timed beats untimed, then a person's or publisher's beats
  /// on-device or agent ones, and among equals the latest wins.
  public private(set) var transcripts: [String: TranscriptRecord] = [:]
  /// Playlists by ID, archived ones included.
  public private(set) var playlists: [String: Playlist] = [:]
  /// episode → recording digest → the chapters recorded for it.
  public private(set) var chapters: [String: [String: ChapterSet]] = [:]

  public init(_ view: ReplicaView) {
    authenticatedLibraryID = view.libraryID
    var seenIDs: Set<String> = []
    var repeatedIDs: Set<String> = []
    for entry in view.admitted where !seenIDs.insert(entry.operation.id).inserted {
      repeatedIDs.insert(entry.operation.id)
    }
    for entry in view.admitted {
      if entry.operation.kind == Podcasts.Kind.naturalEndBatch,
        repeatedIDs.contains(entry.operation.id) {
        naturalEndIntegrityConflicts.insert(entry.operation.id)
        continue
      }
      if (entry.operation.kind == Podcasts.Kind.legacyBridgeImport || entry.operation.kind == LegacyPodcastStateImport.kind || entry.operation.kind == PodcastSourcePublication.kind),
        repeatedIDs.contains(entry.operation.id)
      {
        if entry.operation.kind == PodcastSourcePublication.kind { podcastSourceConflicts.insert(entry.operation.id) }
        else { legacyBridgeIntegrityConflicts.insert(entry.operation.id) }
        continue
      }
      let relevant = entry.operation.kind == Podcasts.Kind.preferenceBatch
        || (entry.operation.kind == Podcasts.Kind.showSettings && entry.operation.payload["speed"] != nil)
      let ambiguousPreferenceRevision = relevant && repeatedIDs.contains(entry.operation.id)
      if ambiguousPreferenceRevision { preferenceIntegrityConflicts.insert(entry.operation.id) }
      apply(entry.operation, by: entry.authorLabel, authorID: entry.author, authorRole: entry.authorRole,
        ambiguousPreferenceRevision: ambiguousPreferenceRevision)
    }
  }

  public func notes(for episode: String) -> [Note] {
    notes.values.filter { $0.episode == episode }.sorted { ($0.seconds ?? -1, $0.sequence) < ($1.seconds ?? -1, $1.sequence) }
  }

  /// Segments to skip for a given audio file, or none.
  public func segments(for episode: String, audio: String) -> [Segment] { segments[episode]?[audio]?.segments ?? [] }

  private static func transcriptRank(_ source: String) -> Int {
    switch source {
    case "publisher": 2
    case "person": 3
    default: 1
    }
  }

  private mutating func applyContent(_ operation: ColophonOperation, by author: String, authorID: String) -> Bool {
    let payload = operation.payload
    switch operation.kind {
    case Podcasts.ContentKind.addNote:
      guard let id = payload["note"]?.string, notes[id] == nil, let episode = payload["episode"]?.string,
        let text = payload["text"]?.string
      else { return true }
      let anchor = TranscriptNoteAnchor(json: payload["transcriptAnchor"])
      notes[id] = Note(id: id, episode: episode, show: payload["show"]?.string ?? "", seconds: payload["seconds"]?.double,
        text: text, quote: anchor?.quote ?? payload["quote"]?.string, origin: payload["origin"]?.string ?? "person",
        authorID: authorID, author: author, creationRevision: operation.id,
        lastTextEditorID: authorID, lastTextEditorLabel: author, anchor: anchor,
        hasAnchorClaim: payload["transcriptAnchor"] != nil, sequence: notes.count, revision: operation.id,
        created: operation.created)
    case Podcasts.ContentKind.editNote, Podcasts.ContentKind.resolveNote:
      guard let id = payload["note"]?.string, var note = notes[id], let text = payload["text"]?.string else { return true }
      if let expect = payload["expect"]?.string, expect != note.revision {
        note.alternatives.append(text)
      } else {
        note.text = text
        note.revision = operation.id
        note.lastTextEditorID = authorID
        note.lastTextEditorLabel = author
        if operation.kind == Podcasts.ContentKind.resolveNote { note.alternatives = [] }
      }
      notes[id] = note
    case Podcasts.ChapterKind.save:
      guard let episode = payload["episode"]?.string, let audio = payload["audio"]?.string,
        audio.count == 64, audio.allSatisfy(\.isHexDigit), let source = payload["source"]?.string
      else { return true }
      // Generated chapters never replace the person's own for the same recording.
      if source != "person", chapters[episode]?[audio]?.source == "person" { return true }
      let entries = (payload["entries"]?.array ?? []).compactMap { value -> ChapterSet.Entry? in
        guard let object = value.object, let start = object["start"]?.double, start.isFinite, start >= 0,
          let title = object["title"]?.string?.trimmingCharacters(in: .whitespacesAndNewlines), !title.isEmpty
        else { return nil }
        return ChapterSet.Entry(start: start, title: String(title.prefix(160)))
      }.sorted { $0.start < $1.start }
      guard !entries.isEmpty else { return true }
      chapters[episode, default: [:]][audio] = ChapterSet(audio: audio, entries: entries, source: source,
        origin: payload["origin"]?.string, by: author)
    case Podcasts.PlaylistKind.save:
      guard let saved = Playlist(payload: payload, revision: operation.id) else { return true }
      if let current = playlists[saved.id], let expect = payload["expect"]?.string, expect != current.revision {
        // Saved without seeing the latest version: keep it beside the current one.
        playlists[saved.id]?.competing.append(saved)
      } else {
        playlists[saved.id] = saved
      }
    case Podcasts.ContentKind.deleteNote:
      if let id = payload["note"]?.string { notes[id] = nil }
    case Podcasts.ContentKind.segments:
      guard let episode = payload["episode"]?.string, let audio = payload["audio"]?.string,
        let source = payload["source"]?.string
      else { return true }
      // Detection never replaces a person's review of the same audio.
      if source != "person", segments[episode]?[audio]?.source == "person" { return true }
      let list = (payload["segments"]?.array ?? []).compactMap { value -> Segment? in
        guard let object = value.object, let start = object["start"]?.double, let end = object["end"]?.double, end > start
        else { return nil }
        return Segment(start: start, end: end, kind: object["kind"]?.string ?? "sponsor")
      }.sorted { $0.start < $1.start }
      segments[episode, default: [:]][audio] = SegmentSet(audio: audio, segments: list, source: source,
        detector: payload["detector"]?.string, by: author)
    case Podcasts.ContentKind.transcript:
      guard let episode = payload["episode"]?.string, let source = payload["source"]?.string,
        let blob = BlobRef(json: payload["blob"])
      else { return true }
      let timed = payload["timed"]?.bool ?? false
      // Timed beats untimed (follow-along and tap-to-seek need times); then a person's or the
      // publisher's beats on-device or agent; among equals the latest wins.
      if let current = transcripts[episode],
        (current.timed ? 1 : 0, Self.transcriptRank(current.source)) > (timed ? 1 : 0, Self.transcriptRank(source))
      {
        return true
      }
      let audio = payload["audio"]?.string.flatMap { $0.count == 64 && $0.allSatisfy(\.isHexDigit) ? $0 : nil }
      transcripts[episode] = TranscriptRecord(source: source, language: payload["language"]?.string, blob: blob,
        timed: timed, by: author, audio: audio)
    default:
      return false
    }
    return true
  }

  private mutating func apply(_ operation: ColophonOperation, by author: String, authorID: String,
    authorRole: MemberRole, ambiguousPreferenceRevision: Bool)
  {
    if applyContent(operation, by: author, authorID: authorID) { return }
    let payload = operation.payload
    switch operation.kind {
    case Podcasts.Kind.follow:
      guard let id = payload["show"]?.string, let feed = payload["feed"]?.string else { return }
      var show = shows[id] ?? Show(id: id, feed: feed, title: payload["title"]?.string ?? feed, following: true)
      show.following = true
      if let raw = preferences["playback.show:" + id + ".speed"] {
        show.speed = Double(raw)
      }
      shows[id] = show
      showRevisions[id] = PlaybackPreferenceBatch.revision(authorID: authorID, operation: operation)
    case Podcasts.Kind.unfollow:
      if let id = payload["show"]?.string {
        shows[id]?.following = false
        showRevisions[id] = PlaybackPreferenceBatch.revision(authorID: authorID, operation: operation)
      }
    case Podcasts.Kind.showSettings:
      guard let id = payload["show"]?.string, var show = shows[id] else { return }
      if !ambiguousPreferenceRevision, let speed = payload["speed"]?.double {
        show.speed = speed
        let key = "playback.show:" + id + ".speed"
        preferences[key] = String(speed)
        preferenceRevisionByKey[key] = PlaybackPreferenceBatch.revision(authorID: authorID,
          operation: operation)
      }
      if let intro = payload["skipIntro"]?.double { show.skipIntro = intro }
      if let outro = payload["skipOutro"]?.double { show.skipOutro = outro }
      shows[id] = show
      showRevisions[id] = PlaybackPreferenceBatch.revision(authorID: authorID, operation: operation)
    case Podcasts.Kind.preferenceBatch:
      guard !ambiguousPreferenceRevision, authorRole == .app || authorRole == .device,
        let batch = PlaybackPreferenceBatch.decode(operation)
      else { return }
      let commandKey = PlaybackPreferenceBatch.signerKey(authorID, batch.commandID)
      if let previous = preferenceReceipts[commandKey] {
        if previous.digest != batch.commandDigest { preferenceCommandConflicts.insert(commandKey) }
        return
      }
      let stale = batch.changes.contains { change in
        (batch.expected[change.key] ?? nil) != preferenceRevisionByKey[change.key]
      }
      if !stale {
        let revision = PlaybackPreferenceBatch.revision(authorID: authorID, operation: operation)
        for change in batch.changes {
          preferences[change.key] = change.value
          preferenceRevisionByKey[change.key] = revision
          if case .show(let id) = change.scope {
            if change.field == "speed" { shows[id]?.speed = Double(change.value) }
            showRevisions[id] = revision
          }
        }
      }
      preferenceReceipts[commandKey] = PlaybackPreferenceBatchReceipt(commandID: batch.commandID,
        authorID: authorID, operationID: operation.id,
        revision: PlaybackPreferenceBatch.revision(authorID: authorID, operation: operation),
        digest: batch.commandDigest,
        outcome: stale ? .stale : .applied, changedKeys: batch.changes.map(\.key))
    case Podcasts.Kind.naturalEndBatch:
      guard authorRole == .app || authorRole == .device,
        let batch = PlaybackNaturalEndBatch.decode(operation),
        batch.libraryID == authenticatedLibraryID else { return }
      let keyed = batch.events.map { event in
        (event, PlaybackNaturalEndBatch.signerKey(authorID, event.eventID))
      }
      // A prior conflicting use poisons the event name for every subsequent batch, even
      // when its original receipt matches. Never let another member apply by filtering it.
      guard keyed.allSatisfy({ !naturalEndEventConflicts.contains($0.1) }) else { return }
      // A reused event name with changed meaning rejects the whole operation, including its
      // otherwise unreceipted members. Existing matching receipts remain immutable.
      var digests: [String: String] = [:]
      for (event, key) in keyed {
        guard let digest = try? PlaybackNaturalEndBatch.eventDigest(event,
          libraryID: batch.libraryID, baseQueue: batch.baseQueue,
          expectedQueueRevision: batch.expectedQueueRevision) else { return }
        digests[key] = digest
        if let prior = naturalEndReceipts[key], prior.digest != digest {
          naturalEndEventConflicts.insert(key)
          return
        }
      }
      let pending = keyed.filter { naturalEndReceipts[$0.1] == nil }
      guard !pending.isEmpty else { return }
      let stale = queueRevision != batch.expectedQueueRevision || queue != batch.baseQueue
        || pending.contains { event, _ in
          let current = episodes[event.episodeID]
          return (current != nil && current?.show != event.showID)
            || current?.positionRevision != event.expectedPositionRevision
            || current?.stateRevision != event.expectedStateRevision
        }
      let revision = PlaybackPreferenceBatch.revision(authorID: authorID, operation: operation)
      if !stale {
        let endedIDs = Set(pending.map { $0.0.episodeID })
        for (event, _) in pending {
          var episode = episodes[event.episodeID]
            ?? Episode(id: event.episodeID, show: event.showID, updated: operation.created)
          episode.seconds = event.endSeconds
          episode.duration = event.actualDuration
          episode.positionRevision = operation.id
          episode.consumption = "completed"
          episode.stateRevision = operation.id
          episode.updated = operation.created
          episodes[event.episodeID] = episode
        }
        var seen: Set<String> = []
        queue = queue.filter { !endedIDs.contains($0) && seen.insert($0).inserted }
        queuedEpisodeMetadata = queuedEpisodeMetadata.filter { seen.contains($0.key) }
        queueRevision = revision
      }
      for (event, key) in pending {
        naturalEndReceipts[key] = PlaybackNaturalEndReceipt(eventID: event.eventID,
          authorID: authorID, operationID: operation.id, revision: revision,
          digest: digests[key] ?? "", outcome: stale ? .stale : .applied)
      }
    case Podcasts.Kind.legacyBridgeImport:
      // Admission verifies the signer/grant; this additional role fence also rejects an
      // agent's raw MCP/Replica command that bypassed the typed local import service.
      guard authorRole == .app || authorRole == .device,
        let batch = LegacyBridgeImport.decode(operation),
        let authenticatedLibraryID, batch.targetLibraryID == authenticatedLibraryID
      else { return }
      let key = LegacyBridgeImport.signerKey(authorID, batch.commandID)
      if let previous = legacyBridgeReceipts[key] {
        if previous.commandDigest != batch.commandDigest { legacyBridgeCommandConflicts.insert(key) }
        return
      }
      let revision = PlaybackPreferenceBatch.revision(authorID: authorID, operation: operation)
      let rootKey = LegacyBridgeImport.rootKey(batch.lineageID, batch.sourceRoot)
      if let previous = legacyBridgeRootReceipts[rootKey] {
        guard previous.crosswalkDigest == batch.crosswalkDigest,
          previous.sharedInventoryDigest == batch.sharedInventoryDigest,
          previous.sourceDescriptor == batch.sourceDescriptor else {
          legacyBridgeSourceRootConflicts.insert(rootKey)
          return
        }
        legacyBridgeReceipts[key] = LegacyBridgeImportReceipt(commandID: batch.commandID,
          authorID: authorID, operationID: operation.id, revision: revision,
          targetLibraryID: batch.targetLibraryID, lineageID: batch.lineageID,
          sourceRoot: batch.sourceRoot, crosswalkDigest: batch.crosswalkDigest,
          sharedInventoryDigest: batch.sharedInventoryDigest,
          sourceDescriptor: batch.sourceDescriptor,
          commandDigest: batch.commandDigest, outcome: .reused, appliedShowIDs: [],
          skippedShowIDs: batch.feeds.map(\.targetShowID))
        return
      }
      let currentRoot = legacyBridgeLineageRoots[batch.lineageID]
      // First internal bridge version admits a single semantic source root per lineage.
      // A different root needs whole-history lineage proof on every device, not only this
      // podcast subset, so it is quarantined even if it names the previous root as parent.
      let changedRoot = currentRoot != nil && currentRoot != batch.sourceRoot
      if changedRoot { legacyBridgeSourceRootConflicts.insert(rootKey) }
      let priorInventory = legacyBridgeSourceOperationHashes[batch.lineageID] ?? [:]
      let proposedInventory = Dictionary(uniqueKeysWithValues: batch.sharedOperationInventory.map {
        ($0.operationID, $0.digest)
      })
      let changedSourceRecord = priorInventory.contains { proposedInventory[$0.key] != $0.value }
      let staleLineage = batch.expectedLineageRoot != currentRoot || batch.parentSourceRoot != currentRoot
      let staleShows = batch.feeds.contains { feed in
        (batch.expectedShowHeads[feed.targetShowID] ?? nil) != showRevisions[feed.targetShowID]
      }
      let stale = staleLineage || staleShows
      if changedSourceRecord { legacyBridgeSourceRecordConflicts.insert(rootKey) }
      var applied: [String] = []
      var skipped: [String] = []
      if !stale && !changedRoot && !changedSourceRecord {
        for feed in batch.feeds {
          let id = feed.targetShowID
          // A native unfollow can precede any local show object. Its revision still wins.
          if shows[id] == nil && showRevisions[id] == nil {
            shows[id] = Show(id: id, feed: feed.feedURL, title: feed.title, following: true)
            showRevisions[id] = revision
            applied.append(id)
          } else { skipped.append(id) }
        }
        legacyBridgeLineageRoots[batch.lineageID] = batch.sourceRoot
        legacyBridgeSourceOperationHashes[batch.lineageID] = proposedInventory
      }
      let receipt = LegacyBridgeImportReceipt(commandID: batch.commandID, authorID: authorID,
        operationID: operation.id, revision: revision, targetLibraryID: batch.targetLibraryID,
        lineageID: batch.lineageID, sourceRoot: batch.sourceRoot,
        crosswalkDigest: batch.crosswalkDigest, sharedInventoryDigest: batch.sharedInventoryDigest,
        sourceDescriptor: batch.sourceDescriptor,
        commandDigest: batch.commandDigest,
        outcome: changedRoot || changedSourceRecord ? .conflict : (stale ? .stale : .applied),
        appliedShowIDs: applied, skippedShowIDs: skipped)
      legacyBridgeReceipts[key] = receipt
      if !stale && !changedRoot && !changedSourceRecord { legacyBridgeRootReceipts[rootKey] = receipt }
    case PodcastSourcePublication.kind:
      guard authorRole == .app || authorRole == .device,
        let batch = PodcastSourcePublication.decode(operation), batch.libraryID == authenticatedLibraryID else { return }
      guard acceptsSource(facts: batch.facts, actions: batch.actions) else {
        podcastSourceConflicts.insert(operation.id); return
      }
      if podcastSourceReceipts.contains(batch.digest) { return }
      for fact in batch.facts { podcastSourceFacts[fact.key] = fact }
      for action in batch.actions where podcastSourceActions[action.actionID] == nil {
        guard let fact = podcastSourceFacts[action.factKey] else { continue }
        let showID = Podcasts.showID(feed: action.feed)
        let episodeID = action.guid.map { Podcasts.episodeID(feed: action.feed, guid: $0) }
        let current: String?
        switch fact.kind {
        case "follow", "unfollow": current = showRevisions[showID]
        case "position": current = episodeID.flatMap { episodes[$0]?.positionRevision }
        default: current = episodeID.flatMap { episodes[$0]?.stateRevision }
        }
        let applied = action.mode == .baseline ? current == nil : current == action.expectedRevision
        let revision = operation.id + ":" + action.actionID
        let receipt = PodcastSourceActionReceipt(action: action, digest: action.digest, revision: revision, applied: applied)
        podcastSourceActions[action.actionID] = receipt
        podcastSourceRevisions[revision] = receipt
        guard applied else { continue }
        switch fact.kind {
        case "follow", "unfollow":
          var show = shows[showID] ?? Show(id: showID, feed: action.feed, title: fact.metadata["title"]?.string ?? action.feed, following: false)
          show.following = fact.kind == "follow"
          shows[showID] = show; showRevisions[showID] = revision
        case "position", "consumption":
          guard let id = episodeID else { continue }
          var episode = episodes[id] ?? Episode(id: id, show: showID, updated: fact.sourceDate)
          if fact.kind == "position", let seconds = fact.body["seconds"]?.double {
            episode.seconds = seconds; episode.positionRevision = revision
            if action.mode == .baseline { importedPositionRevisions.insert(revision) }
          } else if let consumption = fact.body["consumption"]?.string {
            episode.consumption = consumption; episode.stateRevision = revision
          }
          if action.mode == .live || episodes[id] == nil { episode.updated = fact.sourceDate }
          episodes[id] = episode
        default: break
        }
      }
      podcastSourceReceipts.insert(batch.digest)
    case LegacyPodcastStateImport.kind:
      guard authorRole == .app || authorRole == .device,
        let batch = LegacyPodcastStateImport.decode(operation),
        batch.libraryID == authenticatedLibraryID,
        let source = legacyBridgeRootReceipts[LegacyBridgeImport.rootKey(batch.lineageID, batch.sourceRoot)],
        source.sourceDescriptor == nil else { return }
      if legacyPodcastStateReceipts.contains(batch.digest) { return }
      let keyed = batch.records.map { record in
        (record, LegacyPodcastStateImport.recordKey(lineageID: batch.lineageID,
          sourceRoot: batch.sourceRoot, legacyID: record.legacyID))
      }
      guard keyed.allSatisfy({ record, key in
        guard let digest = try? record.digest else { return false }
        return legacyPodcastStateDigests[key].map { $0 == digest } ?? true
      }) else { return }
      let sourceShows = Set(source.appliedShowIDs + source.skippedShowIDs)
      for (record, key) in keyed where legacyPodcastStateDigests[key] == nil {
        guard sourceShows.contains(record.showID) else { return }
      }
      for (record, key) in keyed where legacyPodcastStateDigests[key] == nil {
        var episode = episodes[record.episodeID] ?? Episode(id: record.episodeID, show: record.showID, updated: record.updated)
        if episode.positionRevision == nil, let seconds = record.seconds {
          episode.seconds = seconds
          episode.positionRevision = operation.id
          importedPositionRevisions.insert(operation.id)
        }
        if episode.stateRevision == nil, let consumption = record.consumption {
          episode.consumption = consumption
          episode.stateRevision = operation.id
        }
        // Existing native dates describe native activity, not the import moment.
        if episodes[record.episodeID] == nil { episode.updated = record.updated }
        episodes[record.episodeID] = episode
        legacyPodcastStateDigests[key] = try? record.digest
      }
      legacyPodcastStateReceipts.insert(batch.digest)
    case Podcasts.Kind.setState:
      guard let id = payload["episode"]?.string, let consumption = payload["consumption"]?.string else { return }
      var episode = episodes[id] ?? Episode(id: id, show: payload["show"]?.string ?? "", updated: operation.created)
      if let expect = payload["expect"]?.string, expect != episode.stateRevision { conflicts.append(operation.id); return }
      episode.consumption = consumption
      episode.stateRevision = operation.id
      episode.updated = operation.created
      episodes[id] = episode
    case Podcasts.Kind.position:
      guard let id = payload["episode"]?.string, let seconds = payload["seconds"]?.double else { return }
      var episode = episodes[id] ?? Episode(id: id, show: payload["show"]?.string ?? "", updated: operation.created)
      // A deliberate seek always applies. Passive progress applies when its writer saw the current
      // position, or when it moves forward; a stale passive report never undoes a rewind.
      let informed = payload["expect"]?.string == episode.positionRevision
      let importedBaseline = episode.positionRevision.map { importedPositionRevisions.contains($0) } ?? false
      guard importedBaseline || payload["deliberate"]?.bool == true || informed || seconds > episode.seconds else { return }
      episode.seconds = seconds
      if let duration = payload["duration"]?.double { episode.duration = duration }
      episode.positionRevision = operation.id
      episode.updated = operation.created
      episodes[id] = episode
    case Podcasts.Kind.recoverPosition:
      let keys: Set<String> = ["episode", "show", "seconds", "duration", "expectedPosition", "expectedState", "inProgress"]
      guard operation.v == 1, Set(payload.keys) == keys,
        let id = payload["episode"]?.string, !id.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, id.utf8.count <= 256,
        !id.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains),
        let show = payload["show"]?.string, !show.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, show.utf8.count <= 256,
        !show.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains),
        let seconds = payload["seconds"]?.double, seconds.isFinite, seconds >= 0,
        let rawDuration = payload["duration"],
        rawDuration == .null || rawDuration.double.map({ $0.isFinite && $0 >= 0 }) == true,
        QueuedEpisodeMetadata.validRevision(payload["expectedPosition"]),
        QueuedEpisodeMetadata.validRevision(payload["expectedState"]),
        let inProgress = payload["inProgress"]?.bool else { return }
      let observed = episodes[id]
      guard observed?.positionRevision == payload["expectedPosition"]?.string,
        observed?.stateRevision == payload["expectedState"]?.string,
        observed == nil || observed?.show == show else { return }
      var episode = observed ?? Episode(id: id, show: show, updated: operation.created)
      episode.seconds = seconds
      if let duration = rawDuration.double { episode.duration = duration }
      episode.positionRevision = operation.id
      if inProgress { episode.consumption = "inProgress"; episode.stateRevision = operation.id }
      episode.updated = operation.created
      episodes[id] = episode
    case Podcasts.Kind.queue:
      guard let values = payload["episodes"]?.array else { return }
      // Preserve the established v1 IDs behavior, even when optional metadata is malformed.
      queue = values.compactMap(\.string)
      queueRevision = Podcasts.queueRevision(authorID: authorID, operation: operation)
      let ids = Set(queue)
      queuedEpisodeMetadata = queuedEpisodeMetadata.filter { ids.contains($0.key) }
      if operation.v == 1, let raw = payload["metadata"], let additions = QueuedEpisodeMetadata.decodeBatch(raw),
        Set(additions.keys).isSubset(of: ids),
        let merged = QueuedEpisodeMetadata.merging(queuedEpisodeMetadata, additions) {
        queuedEpisodeMetadata = merged
      }
    case Podcasts.Kind.queueRetain:
      guard operation.v == 1, Set(payload.keys) == ["metadata", "expectedQueueRevision"],
        QueuedEpisodeMetadata.validRevision(payload["expectedQueueRevision"]),
        queueRevision == payload["expectedQueueRevision"]?.string,
        let raw = payload["metadata"], let additions = QueuedEpisodeMetadata.decodeBatch(raw),
        Set(additions.keys).isSubset(of: Set(queue)),
        let merged = QueuedEpisodeMetadata.merging(queuedEpisodeMetadata,
          additions.filter { queuedEpisodeMetadata[$0.key] == nil }) else { return }
      queuedEpisodeMetadata = merged
    default:
      break
    }
  }

  /// Validate the complete batch before mutating either ledger or canonical state.
  func acceptsSource(facts: [PodcastSourceFact], actions: [PodcastSourceAction]) -> Bool {
    var proposed: [String: PodcastSourceFact] = [:]
    for fact in facts {
      if let old = proposed[fact.key] ?? podcastSourceFacts[fact.key], old != fact { return false }
      proposed[fact.key] = fact
    }
    func retained(_ key: String) -> PodcastSourceFact? { proposed[key] ?? podcastSourceFacts[key] }
    for action in actions {
      if let old = podcastSourceActions[action.actionID], old.digest != action.digest { return false }
      guard let fact = retained(action.factKey), ["follow", "unfollow", "position", "consumption"].contains(fact.kind) else { return false }
      if let feed = fact.metadata["feedURL"]?.string, feed != action.feed { return false }
      if fact.kind == "position", fact.body["seconds"]?.double == nil || fact.body["passageAnchor"]?.string != nil { return false }
      if ["position", "consumption"].contains(fact.kind) {
        guard let guid = action.guid else { return false }
        if let sourceGUID = fact.metadata["guid"]?.string, sourceGUID != guid { return false }
        let rss = Canonical.digest(Data((action.feed + "|" + guid).utf8))
        let item = fact.metadata["itemID"]?.string
        let native = Podcasts.episodeID(feed: action.feed, guid: guid)
        if item != rss && item != native {
          let identity = action.identityFactKey.flatMap { retained($0) } ?? fact
          guard identity.metadata["itemID"] == fact.metadata["itemID"],
            let member = action.rssMemberID, member == rss,
            identity.metadata["rssMemberIDs"]?.array?.contains(.string(member)) == true else { return false }
        }
        if let member = action.rssMemberID, member != rss { return false }
      } else if action.guid != nil || action.rssMemberID != nil || fact.metadata["feedURL"]?.string != action.feed { return false }
    }
    return true
  }

  public var following: [Show] { shows.values.filter(\.following).sorted { $0.title < $1.title } }
}
