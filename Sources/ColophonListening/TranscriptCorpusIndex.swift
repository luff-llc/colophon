import ColophonAuthority
import ColophonCore
import ColophonReplica
import Foundation

/// A rebuildable, profile-local index. The replica remains the authority and source of truth.
/// Only selected versions are searched; historical references still resolve through the signed
/// log. Memory holds lexical postings and offsets, with no full document or snippet hot cache.
/// Queries materialize and validate at most 100 source passages before returning a page.
public actor TranscriptCorpusIndex {
  private let replica: Replica
  private let cacheURL: URL?
  private var libraryID: String?
  private var documents: Set<SharedTranscriptReference> = []
  private var sources: [SharedTranscriptReference: TranscriptCorpusSource] = [:]
  private struct Passage: Codable {
    let reference: SharedTranscriptReference
    let start: Int
    let length: Int
    let firstOffsets: [String: Int]
    var terms: Set<String> { Set(firstOffsets.keys) }
    var id: String { "\(reference.revision):\(start)" }
  }
  private var passages: [String: Passage] = [:]
  private var postings: [String: Set<String>] = [:]
  private var passagesByReference: [SharedTranscriptReference: [String]] = [:]
  private var missing: Set<SharedTranscriptReference> = []
  private var invalid: Set<SharedTranscriptReference> = []
  private var heldCount = 0
  private var decodedDocumentCount = 0
  private var loadedCache = false
  private var generation = ""
  private var inventorySignature = ""
  private struct Cache: Codable {
    let version: Int
    let libraryID: String
    let documents: [CachedDocument]
  }
  private struct CachedDocument: Codable {
    let reference: SharedTranscriptReference
    let passages: [Passage]
  }

  /// `cacheURL` must be inside this library's private local profile, never a sync folder.
  /// It contains private lexical hints protected by owner-only mode; result quotes always
  /// come from revalidated immutable source blobs, never from the cache.
  public init(replica: Replica, cacheURL: URL? = nil) {
    self.replica = replica
    self.cacheURL = cacheURL
  }

  @discardableResult public func refresh(rebuild: Bool = false) throws -> TranscriptCorpusCoverage {
    do { try requireCurrentRead() } catch {
      invalidate()
      throw error
    }
    let authority = try replica.authority()
    if rebuild || (libraryID != nil && libraryID != authority.libraryID) { invalidate() }
    libraryID = authority.libraryID
    let view = try replica.read(Podcasts.namespace)
    var ids: Set<String> = []
    for entry in view.admitted where !ids.insert(entry.operation.id).inserted {
      invalidate()
      throw SharedTranscriptError.duplicateOperationID(entry.operation.id)
    }
    let signature = "\(authority.libraryID):\(authority.latest):"
      + view.admitted.map { $0.operation.id }.joined(separator: "\u{0}") + "|"
      + view.held.map { $0.operation.id }.joined(separator: "\u{0}")
    let inventoryChanged = signature != inventorySignature
    if inventoryChanged {
      let listening = Listening(view)
      var selectedByEpisode: [String: TranscriptCorpusSource] = [:]
      for entry in view.admitted {
        let op = entry.operation
        guard op.kind == Podcasts.ContentKind.transcript,
          let episode = op.payload["episode"]?.string, let show = op.payload["show"]?.string,
          let blob = BlobRef(json: op.payload["blob"]), let record = listening.transcripts[episode],
          record.blob == blob, record.source == op.payload["source"]?.string,
          record.language == op.payload["language"]?.string,
          record.timed == (op.payload["timed"]?.bool ?? false)
        else { continue }
        // Match SharedTranscriptService.reference's final candidate when identical immutable
        // content has more than one operation. Do not introduce another selection policy.
        let ref = SharedTranscriptReference(libraryID: authority.libraryID, episode: episode,
          show: show, revision: op.id, blob: blob)
        selectedByEpisode[episode] = TranscriptCorpusSource(reference: ref, source: record.source,
          language: record.language, timed: record.timed, audio: op.payload["audio"]?.string,
          authorID: entry.author, authorLabel: entry.authorLabel,
          showTitle: listening.shows[show]?.title ?? show)
      }
      let selected = Dictionary(uniqueKeysWithValues: selectedByEpisode.values.map { ($0.reference, $0) })
      heldCount = view.held.filter { $0.operation.kind == Podcasts.ContentKind.transcript }.count
      for reference in Array(documents) where selected[reference] == nil { remove(reference) }
      sources = selected
      missing = missing.intersection(selected.keys)
      invalid = invalid.intersection(selected.keys)
      inventorySignature = signature
    }
    let selected = sources
    var changed = inventoryChanged
    var cached: [SharedTranscriptReference: [Passage]] = [:]
    if !loadedCache {
      loadedCache = true
      if !rebuild, let cacheURL, let bytes = try? Data(contentsOf: cacheURL),
        let cache = try? Canonical.decode(Cache.self, from: bytes), cache.version == 2,
        cache.libraryID == authority.libraryID
      {
        for entry in cache.documents where selected[entry.reference] != nil {
          guard entry.passages.allSatisfy({ passage in
            passage.reference == entry.reference && passage.start >= 0 && passage.length > 0
              && passage.length <= 8_000 && passage.firstOffsets.values.allSatisfy { $0 >= 0 && $0 < passage.length }
          }) else { continue }
          cached[entry.reference] = entry.passages
        }
      }
    }
    for reference in selected.keys.sorted(by: { $0.revision < $1.revision }) where !documents.contains(reference) {
      // Check actual retention even for a persisted cache. Late blobs are retried on refresh.
      do {
        guard let data = try replica.blob(reference.blob, in: Podcasts.namespace) else {
          if missing.insert(reference).inserted { changed = true }
          if invalid.remove(reference) != nil { changed = true }
          continue
        }
        if let hints = cached[reference] { install(hints, reference: reference) }
        else {
          let document = try Canonical.decode(TranscriptDocument.self, from: data)
          decodedDocumentCount += 1
          add(document, reference: reference)
        }
        missing.remove(reference)
        invalid.remove(reference)
        changed = true
      } catch ColophonError.noAccess {
        if missing.insert(reference).inserted { changed = true }
      } catch {
        if invalid.insert(reference).inserted { changed = true }
        if missing.remove(reference) != nil { changed = true }
      }
    }
    if changed || generation.isEmpty {
      generation = try fingerprint()
      persistCache()
    }
    return coverage
  }

  /// Notify after local source eviction or retention changes; only derived postings are
  /// removed. The next refresh reconciles actual local availability without a whole rescan.
  public func retainedSourceChanged(_ reference: SharedTranscriptReference) {
    remove(reference)
    missing.remove(reference)
    invalid.remove(reference)
    generation = ""
    persistCache()
  }

  /// Clears all derived text immediately, including the optional disk cache. Call on profile
  /// switch, explicit retention removal, or authority changes; rebuilding is always safe.
  public func invalidate() {
    documents.removeAll()
    sources.removeAll()
    passages.removeAll()
    passagesByReference.removeAll()
    postings.removeAll()
    missing.removeAll()
    invalid.removeAll()
    heldCount = 0
    libraryID = nil
    loadedCache = false
    generation = ""
    inventorySignature = ""
    if let cacheURL { try? FileManager.default.removeItem(at: cacheURL) }
  }

  public func search(_ query: String, mode: TranscriptCorpusMatchMode = .allTerms, limit: Int = 20, cursor: TranscriptCorpusCursor? = nil)
    throws -> TranscriptCorpusPage
  {
    guard query.utf16.count <= 2_000, limit > 0 else { throw TranscriptCorpusError.invalidQuery }
    _ = try refresh()
    let terms = mode == .question ? TranscriptCorpusLexicon.queryTerms(query) : Set(TranscriptCorpusLexicon.terms(query))
    let required = mode == .allTerms ? terms.count : max(1, Int((Double(terms.count) * 0.6).rounded(.up)))
    let queryDigest = Canonical.digest(Data((mode.rawValue + ":" + terms.sorted().joined(separator: "\u{0}")).utf8))
    if let cursor {
      guard cursor.generation == generation, cursor.queryDigest == queryDigest, cursor.offset >= 0 else {
        throw TranscriptCorpusError.staleCursor
      }
    }
    guard !terms.isEmpty else { return TranscriptCorpusPage(hits: [], coverage: coverage, nextCursor: nil) }
    var candidates: Set<String> = []
    for term in terms { candidates.formUnion(postings[term] ?? []) }
    struct Ranked {
      let passage: Passage
      let source: TranscriptCorpusSource
      let score: Int
      let matchStart: Int
    }
    var matches: [String: Ranked] = [:]
    for id in candidates {
      guard let passage = passages[id], let source = sources[passage.reference] else { continue }
      let covered = terms.intersection(passage.terms)
      guard covered.count >= required,
        let first = covered.compactMap({ passage.firstOffsets[$0] }).min() else { continue }
      let matchStart = passage.start + first
      let key = "\(passage.reference.revision):\(matchStart)"
      let score = covered.count * 100 + max(0, 50 - passage.firstOffsets.count)
      let item = Ranked(passage: passage, source: source, score: score, matchStart: matchStart)
      if let existing = matches[key], existing.score > score
        || (existing.score == score && existing.passage.start < passage.start) { continue }
      matches[key] = item
    }
    let ranked = matches.values.sorted {
      if $0.score != $1.score { return $0.score > $1.score }
      if $0.source.episodeID != $1.source.episodeID { return $0.source.episodeID < $1.source.episodeID }
      if $0.source.reference.revision != $1.source.reference.revision {
        return $0.source.reference.revision < $1.source.reference.revision
      }
      return $0.passage.start < $1.passage.start
    }
    let pageLimit = min(limit, 100)
    var offset = min(cursor?.offset ?? 0, ranked.count)
    var hits: [TranscriptCorpusHit] = []
    var resolved: [SharedTranscriptReference: TranscriptDocument] = [:]
    var sourceChanged = false
    var attempts = 0
    while offset < ranked.count && hits.count < pageLimit && attempts < 100 {
      let item = ranked[offset]
      offset += 1; attempts += 1
      let reference = item.source.reference
      do {
        let document: TranscriptDocument
        if let cached = resolved[reference] { document = cached }
        else {
          document = try SharedTranscriptService(replica: replica).resolve(reference)
          resolved[reference] = document
        }
        let start = item.passage.start
        let length = item.passage.length
        guard start <= document.text.utf16.count, length <= document.text.utf16.count - start,
          let range = Range(NSRange(location: start, length: length), in: document.text)
        else { remove(reference); invalid.insert(reference); sourceChanged = true; continue }
        let quote = String(document.text[range])
        let actualTokens = TranscriptCorpusLexicon.tokens(quote)
        guard terms.intersection(actualTokens.map(\.term)).count >= required,
          let actualFirst = actualTokens.first(where: { terms.contains($0.term) }) else {
          remove(reference); invalid.insert(reference); sourceChanged = true; continue
        }
        let anchor = TranscriptNoteAnchor(reference: reference, startUTF16: start, lengthUTF16: length, quote: quote)
        hits.append(TranscriptCorpusHit(source: item.source, anchor: anchor, score: item.score,
          matchStartUTF16: start + actualFirst.start))
      } catch SharedTranscriptError.missingTranscript {
        remove(reference); missing.insert(reference); sourceChanged = true
      }
    }
    if sourceChanged {
      generation = try fingerprint(); persistCache()
      return TranscriptCorpusPage(hits: hits, coverage: coverage, nextCursor: nil)
    }
    let next = offset < ranked.count
      ? TranscriptCorpusCursor(generation: generation, queryDigest: queryDigest, offset: offset) : nil
    return TranscriptCorpusPage(hits: hits, coverage: coverage, nextCursor: next)
  }

  public func resolve(anchor: TranscriptNoteAnchor) throws -> TranscriptDocument {
    let document = try SharedTranscriptService(replica: replica).resolve(anchor.reference)
    guard anchor.matches(document) else { throw SharedTranscriptError.wrongCitation }
    return document
  }

  public func document(for reference: SharedTranscriptReference) throws -> TranscriptDocument {
    try SharedTranscriptService(replica: replica).resolve(reference)
  }

  public var coverage: TranscriptCorpusCoverage {
    TranscriptCorpusCoverage(selectedCount: sources.count, indexedCount: documents.count,
      missingBlobCount: missing.count, invalidBlobCount: invalid.count, heldCount: heldCount,
      decodedDocumentCount: decodedDocumentCount)
  }

  private func add(_ document: TranscriptDocument, reference: SharedTranscriptReference) {
    let entries = TranscriptCorpusLexicon.passages(document.text).map { chunk in
      var offsets: [String: Int] = [:]
      for token in TranscriptCorpusLexicon.tokens(chunk.text) where offsets[token.term] == nil {
        offsets[token.term] = token.start
      }
      return Passage(reference: reference, start: chunk.start, length: chunk.text.utf16.count, firstOffsets: offsets)
    }
    install(entries, reference: reference)
  }

  private func install(_ entries: [Passage], reference: SharedTranscriptReference) {
    documents.insert(reference)
    passagesByReference[reference] = entries.map(\.id)
    for passage in entries {
      passages[passage.id] = passage
      for term in passage.firstOffsets.keys { postings[term, default: []].insert(passage.id) }
    }
  }

  private func remove(_ reference: SharedTranscriptReference) {
    documents.remove(reference)
    for id in passagesByReference.removeValue(forKey: reference) ?? [] {
      guard let passage = passages.removeValue(forKey: id) else { continue }
      for term in passage.terms {
        postings[term]?.remove(id)
        if postings[term]?.isEmpty == true { postings[term] = nil }
      }
    }
  }

  private func fingerprint() throws -> String {
    struct State: Encodable {
      let sources: [TranscriptCorpusSource]
      let indexed: [String]
      let missing: [String]
      let invalid: [String]
      let held: Int
    }
    return Canonical.digest(try Canonical.encode(State(
      sources: sources.values.sorted { $0.reference.revision < $1.reference.revision },
      indexed: documents.map(\.revision).sorted(), missing: missing.map(\.revision).sorted(),
      invalid: invalid.map(\.revision).sorted(), held: heldCount)))
  }

  private func persistCache() {
    guard let cacheURL, let libraryID else { return }
    let cache = Cache(version: 2, libraryID: libraryID,
      documents: documents.map { reference in
        CachedDocument(reference: reference, passages: (passagesByReference[reference] ?? []).compactMap { passages[$0] })
      })
    // Persistence is an optimization. Disk pressure cannot make an otherwise valid corpus
    // unavailable, and a partial/corrupt cache is ignored on the next launch.
    do {
      try FileManager.default.createDirectory(at: cacheURL.deletingLastPathComponent(),
        withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
      try Canonical.encode(cache).write(to: cacheURL, options: .atomic)
      try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: cacheURL.path)
    } catch { }
  }

  private func requireCurrentRead() throws {
    let authority = try replica.authority()
    guard let member = authority.members[replica.identity.id], member.revokedAt == nil,
      let grant = member.current, grant.namespaces.contains(Podcasts.namespace),
      grant.expires.map({ $0 >= .now }) ?? true
    else { throw SharedTranscriptError.noCurrentAccess }
  }
}
