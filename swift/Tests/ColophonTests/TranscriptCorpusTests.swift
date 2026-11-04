import ColophonAuthority
import ColophonCore
import ColophonListening
import ColophonReplica
import ColophonStore
import Foundation
import Darwin
import Testing

struct TranscriptCorpusTests {
  private struct Fixture {
    let store = MemoryStore()
    let root = SoftwareIdentity()
    let person = SoftwareIdentity()
    let replica: Replica
    let holder: AuthorityHolder

    init() throws {
      let (holder, _) = try AuthorityHolder.create(in: store, label: "Corpus", root: root,
        firstMember: person.publicIdentity, memberLabel: "Phone", role: .app,
        custody: .software, namespaces: [Podcasts.namespace])
      self.holder = holder
      replica = Replica(store: store, identity: person)
    }

    func save(_ text: String, episode: String = "episode", language: String = "en") throws -> SharedTranscriptReference {
      let op = try replica.saveTranscript(TranscriptDocument(text: text, words: nil), episode: episode,
        show: "show", source: "publisher", language: language)
      let blob = try #require(BlobRef(json: op.payload["blob"]))
      return SharedTranscriptReference(libraryID: try replica.authority().libraryID,
        episode: episode, show: "show", revision: op.id, blob: blob)
    }
  }

  /// Simulates a provider evicting a retained blob while the signed operation remains.
  /// Every mutable field is protected by this lock; the backing MemoryStore locks itself.
  private final class EvictableStore: RecordStore, @unchecked Sendable {
    let base: MemoryStore
    private let lock = NSLock()
    private var evicted: Set<String> = []
    init(_ base: MemoryStore) { self.base = base }
    func evict(_ path: String) { lock.withLock { _ = evicted.insert(path) } }
    func list(_ directory: String) throws -> [String] { try base.list(directory) }
    func read(_ path: String) throws -> Data? {
      try lock.withLock { evicted.contains(path) ? nil : try base.read(path) }
    }
    func create(_ path: String, _ data: Data) throws { try base.create(path, data) }
    func replace(_ path: String, _ data: Data) throws { try base.replace(path, data) }
  }

  @Test func thousandRetainedTranscriptsFindOldSourceAfterRestartWithoutQueryRedecode() async throws {
    let f = try Fixture()
    let old = try f.save("The oldest harbour transcript keeps a narwhal.", episode: "0000")
    for number in 1...1_000 {
      _ = try f.save("Ordinary recording number \(number).", episode: String(number))
    }
    let cache = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
      .appendingPathComponent("corpus.json")
    defer { try? FileManager.default.removeItem(at: cache.deletingLastPathComponent()) }
    let index = TranscriptCorpusIndex(replica: f.replica, cacheURL: cache)
    let clock = ContinuousClock()
    let coldStart = clock.now
    let first = try await index.search("narwhals")
    let coldDuration = coldStart.duration(to: clock.now)
    #expect(first.coverage.selectedCount == 1_001)
    #expect(first.coverage.indexedCount == 1_001)
    #expect(first.hits.first?.anchor.reference == old)
    let decoded = first.coverage.decodedDocumentCount
    let warmStart = clock.now
    let second = try await index.search("harbour")
    let warmDuration = warmStart.duration(to: clock.now)
    #expect(second.coverage.decodedDocumentCount == decoded)
    let restarted = TranscriptCorpusIndex(replica: f.replica, cacheURL: cache)
    let restartStart = clock.now
    let afterRestart = try await restarted.search("narwhals")
    let restartDuration = restartStart.duration(to: clock.now)
    #expect(afterRestart.coverage.decodedDocumentCount == 0)
    let attributes = try FileManager.default.attributesOfItem(atPath: cache.path)
    let cacheBytes = attributes[.size] as? Int ?? 0
    var usage = rusage()
    let usageResult = getrusage(RUSAGE_SELF, &usage)
    print("Corpus fixture: 1001 short transcripts; cold \(coldDuration), warm \(warmDuration), restart \(restartDuration), lexical cache \(cacheBytes) bytes, process peak resident \(usageResult == 0 ? usage.ru_maxrss : 0) bytes (whole test runner, not index-only).")
    #expect(afterRestart.hits.map(\.anchor) == first.hits.map(\.anchor))
    let rebuilt = try await restarted.refresh(rebuild: true)
    let afterRebuild = try await restarted.search("narwhals")
    #expect(rebuilt.indexedCount == 1_001)
    #expect(afterRebuild.hits == first.hits)
  }

  @Test func incrementalSelectionPinnedHistoryAndUnicodeAnchors() async throws {
    let f = try Fixture()
    let old = try f.save("🐋 Café readers are running. 中文播客讨论海洋。", language: "zh")
    let index = TranscriptCorpusIndex(replica: f.replica)
    let english = try await index.search("cafe run")
    let chinese = try await index.search("中文 海洋")
    let hit = try #require(english.hits.first)
    let document = try await index.resolve(anchor: hit.anchor)
    #expect(hit.anchor.matches(document))
    #expect(chinese.hits.count == 1)
    #expect(chinese.hits.first?.source.language == "zh")
    let initial = english.coverage.decodedDocumentCount
    _ = try f.save("A corrected version about mountains.")
    let selected = try await index.search("海洋")
    #expect(selected.hits.isEmpty)
    #expect(selected.coverage.decodedDocumentCount == initial + 1)
    let retained = try await index.resolve(anchor: hit.anchor)
    #expect(retained.text == document.text)
    #expect(hit.anchor.reference == old)
    let incremental = try await index.search("mountain")
    _ = try await index.refresh(rebuild: true)
    let rebuilt = try await index.search("mountain")
    #expect(incremental.hits == rebuilt.hits)
    let falseSubstring = try await index.search("mount")
    #expect(falseSubstring.hits.isEmpty)
  }

  @Test func lateBlobArrivalAndCorruptCacheNeverFabricateCoverage() async throws {
    let f = try Fixture()
    let ref = try f.save("A delayed otter transcript.")
    let partial = MemoryStore()
    for (path, data) in f.store.snapshot where !path.hasPrefix("blobs/") { try partial.create(path, data) }
    let replica = Replica(store: partial, identity: f.person)
    let index = TranscriptCorpusIndex(replica: replica)
    let missing = try await index.search("otter")
    #expect(missing.hits.isEmpty)
    #expect(missing.coverage.missingBlobCount == 1)
    #expect(missing.coverage.isComplete == false)
    let storedBytes = try f.store.read(LibraryPath.blob(ref.blob.digest))
    let bytes = try #require(storedBytes)
    try partial.create(LibraryPath.blob(ref.blob.digest), bytes)
    let arrived = try await index.search("otter")
    #expect(arrived.hits.count == 1)
    #expect(arrived.coverage.missingBlobCount == 0)
    #expect(arrived.coverage.indexedCount == 1)
    let malformed = TranscriptNoteAnchor(reference: ref, startUTF16: 0, lengthUTF16: 6, quote: "forged")
    await #expect(throws: SharedTranscriptError.wrongCitation) { try await index.resolve(anchor: malformed) }
  }

  @Test func stableBoundedPaginationAndChangedSelectionInvalidatesCursor() async throws {
    let f = try Fixture()
    for number in 0..<27 { _ = try f.save("An otter swims.", episode: "episode-\(number)") }
    let index = TranscriptCorpusIndex(replica: f.replica)
    let first = try await index.search("otters", limit: 7)
    let cursor = try #require(first.nextCursor)
    let second = try await index.search("otters", limit: 7, cursor: cursor)
    let repeated = try await index.search("otters", limit: 7, cursor: cursor)
    #expect(second.hits == repeated.hits)
    let intersection = Set(first.hits.map(\.id)).intersection(second.hits.map(\.id))
    #expect(intersection.isEmpty)
    #expect(first.hits.count == 7)
    #expect(second.hits.count == 7)
    _ = try f.save("A different selected transcript.", episode: "episode-0")
    await #expect(throws: TranscriptCorpusError.staleCursor) {
      try await index.search("otters", limit: 7, cursor: cursor)
    }
  }

  @Test func explicitEvictionUpdatesUnmatchedInventoryAndSourceChecksPreventStaleHits() async throws {
    let f = try Fixture()
    let first = try f.save("An otter swims.", episode: "one")
    let second = try f.save("A narwhal dives.", episode: "two")
    let store = EvictableStore(f.store)
    let index = TranscriptCorpusIndex(replica: Replica(store: store, identity: f.person))
    _ = try await index.refresh()
    store.evict(LibraryPath.blob(first.blob.digest))
    await index.retainedSourceChanged(first)
    let remaining = try await index.search("narwhal")
    #expect(remaining.hits.count == 1)
    #expect(remaining.coverage.indexedCount == 1)
    #expect(remaining.coverage.missingBlobCount == 1)
    store.evict(LibraryPath.blob(second.blob.digest))
    let stale = try await index.search("narwhal")
    #expect(stale.hits.isEmpty)
    #expect(stale.coverage.missingBlobCount == 2)
  }

  @Test func duplicateSignedRevisionCannotBecomeAnAmbiguousSource() async throws {
    let f = try Fixture()
    let peer = SoftwareIdentity()
    try f.holder.admit(peer.publicIdentity, label: "Peer", role: .device,
      custody: .software, namespaces: [Podcasts.namespace], write: true)
    let reference = try f.save("An exact source.")
    let path = try #require(f.store.snapshot.keys.first { $0.hasPrefix("ops/") && $0.hasSuffix("-\(reference.revision).json") })
    let bytes = try #require(f.store.snapshot[path])
    let signed = try Canonical.decode(SignedRecord.self, from: bytes)
    let header = try Canonical.decode(OperationHeader.self, from: signed.body)
    let duplicate = OperationHeader(author: peer.id, namespace: header.namespace, epoch: header.epoch, sealed: header.sealed)
    let record = try SignedRecord(signing: Canonical.encode(duplicate), with: peer)
    try f.store.create(LibraryPath.operation(author: peer.id, clock: 999_999, id: reference.revision), Canonical.encode(record))
    let index = TranscriptCorpusIndex(replica: f.replica)
    await #expect(throws: SharedTranscriptError.duplicateOperationID(reference.revision)) { try await index.refresh() }
    let coverage = await index.coverage
    #expect(coverage.indexedCount == 0)
  }

  @Test func questionStopwordsAndMajorityCoverageRankMoreCompleteEvidenceFirst() async throws {
    let f = try Fixture()
    _ = try f.save("The keeper logged ships and storms.", episode: "complete")
    _ = try f.save("A keeper logged weather.", episode: "partial")
    _ = try f.save("A keeper rests.", episode: "insufficient")
    let index = TranscriptCorpusIndex(replica: f.replica)
    let question = try await index.search("What did the keeper log about ships?", mode: .question)
    #expect(question.hits.first?.source.episodeID == "complete")
    #expect(question.hits.count == 2)
    #expect(question.hits[0].score > question.hits[1].score)
    let empty = try await index.search("what did the", mode: .question)
    #expect(empty.hits.isEmpty)
  }

  @Test func wholeTermCoverageMultiplePassagesAndRevocation() async throws {
    let f = try Fixture()
    _ = try f.save("cats see oceans. " + String(repeating: "padding ", count: 120) + "cats cross oceans.")
    _ = try f.save("category sees oceans.", episode: "false-substring")
    _ = try f.save("cats see rivers.", episode: "partial-query")
    let index = TranscriptCorpusIndex(replica: f.replica)
    let result = try await index.search("cat ocean")
    #expect(result.hits.count == 2)
    #expect(result.hits.allSatisfy { $0.source.episodeID == "episode" })
    try f.holder.revoke(f.person.id)
    await #expect(throws: SharedTranscriptError.noCurrentAccess) { try await index.search("cats") }
    let coverage = await index.coverage
    #expect(coverage.indexedCount == 0)
  }
}
