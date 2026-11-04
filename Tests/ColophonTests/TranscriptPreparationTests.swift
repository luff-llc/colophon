import ColophonAuthority
import ColophonCore
import ColophonListening
import ColophonReplica
import ColophonStore
import Foundation
import Testing

@Suite struct TranscriptPreparationTests {
  private struct Fixture {
    let store = MemoryStore()
    let root = SoftwareIdentity()
    let app = SoftwareIdentity()
    let worker = SoftwareIdentity()
    let other = SoftwareIdentity()
    let audio = Data("exact recording fixture".utf8)
    let library: String
    init() throws {
      let (holder, _) = try AuthorityHolder.create(in: store, label: "Preparation", root: root,
        firstMember: app.publicIdentity, memberLabel: "Phone", role: .app, custody: .software,
        namespaces: [Podcasts.namespace])
      try holder.admit(worker.publicIdentity, label: "Selected Mac", role: .agent, custody: .software,
        namespaces: [Podcasts.namespace], write: true)
      try holder.admit(other.publicIdentity, label: "Another Mac", role: .agent, custody: .software,
        namespaces: [Podcasts.namespace], write: true)
      library = try holder.state().libraryID
    }
    var phone: TranscriptPreparationService { .init(replica: Replica(store: store, identity: app)) }
    var mac: TranscriptPreparationService { .init(replica: Replica(store: store, identity: worker)) }
    var request: TranscriptPreparationRequest {
      .init(id: "prepare-1", libraryID: library, episode: "episode", show: "show",
        recordingDigest: Canonical.digest(audio), language: "en_US", policy: .mac, holdAudio: true)
    }
    var result: TranscriptPreparationResult {
      .init(document: TranscriptDocument(text: "Retained original words.", words: [
        .init(text: "Retained original words.", start: 1, end: 4)]), source: "onDevice",
        receipt: TranscriptSourceReceipt(retrieved: Date(timeIntervalSince1970: 1), engine: "Fixture engine",
          runtime: "Fixture runtime", language: "en_US", recordingDigest: Canonical.digest(audio), completeness: .complete))
    }
    func assign() throws -> TranscriptPreparationAssignment {
      let blob = try phone.replica.putBlob(audio, in: Podcasts.namespace)
      return try phone.request(request, audio: blob, worker: worker.id)
    }
    func revokeWorker() throws {
      try AuthorityHolder(log: AuthorityLog(store: store), root: root).revoke(worker.id)
    }
  }
  private func directory() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appending(path: "transcript-preparation-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
  }

  @Test func partialCheckpointSurvivesFailureAndRestartWithoutBecomingReady() throws {
    let f = try Fixture(); let folder = try directory()
    defer { try? FileManager.default.removeItem(at: folder) }
    let journal = try TranscriptPreparationJournal(directory: folder)
    _ = try journal.enqueue(f.request); _ = try journal.begin(f.request.id)
    var partial = f.result
    partial.receipt.completeness = .partial
    try journal.checkpoint(f.request.id, result: partial)
    try journal.fail(f.request.id, message: "Recognition interrupted")
    let relaunched = try TranscriptPreparationJournal(directory: folder)
    try relaunched.recoverInterrupted()
    let restored = try relaunched.draft(f.request.id)
    #expect(restored == partial)
    #expect(relaunched.record(f.request.id)?.state == .failed)
    #expect(relaunched.record(f.request.id)?.resultDigest == nil)
    #expect(throws: TranscriptPreparationError.notReady) {
      try f.phone.apply(request: f.request, result: partial)
    }
  }

  @Test func cumulativeDraftReplacementCompletionAndDiscardKeepSourcesSeparate() throws {
    let f = try Fixture(); let folder = try directory()
    defer { try? FileManager.default.removeItem(at: folder) }
    let journal = try TranscriptPreparationJournal(directory: folder)
    _ = try journal.enqueue(f.request); _ = try journal.begin(f.request.id)
    var partial = f.result
    partial.receipt.completeness = .partial
    partial.document = TranscriptDocument(text: "First", words: [.init(text: "First", start: 1, end: 2)])
    try journal.checkpoint(f.request.id, result: partial)
    partial.document = f.result.document
    try journal.checkpoint(f.request.id, result: partial)
    let cumulative = try journal.draft(f.request.id)
    #expect(cumulative == partial)
    try journal.ready(f.request.id, result: f.result)
    let reference = try f.phone.apply(request: f.request, result: f.result)
    try journal.applied(f.request.id, revision: reference.revision)
    let completedDraft = try journal.draft(f.request.id)
    #expect(completedDraft == nil)
    try journal.discardDraft(f.request.id)
    let complete = try journal.result(f.request.id)
    #expect(complete == f.result)

    var retry = f.request; retry.id = "retry"
    _ = try journal.enqueue(retry); _ = try journal.begin(retry.id)
    try journal.checkpoint(retry.id, result: partial)
    try journal.discardDraft(retry.id)
    try journal.cancel(retry.id)
    let relaunched = try TranscriptPreparationJournal(directory: folder)
    let discarded = try relaunched.draft(retry.id)
    #expect(discarded == nil)
    let saved = try f.phone.replica.transcript(of: "episode", in: f.phone.replica.state(of: Podcasts.self))
    #expect(saved == f.result.document)
  }

  @Test func retryKeepsFurthestDraftAndRecordingUntilRecognitionCatchesUp() throws {
    let f = try Fixture(); let folder = try directory()
    defer { try? FileManager.default.removeItem(at: folder) }
    let journal = try TranscriptPreparationJournal(directory: folder)
    var request = f.request; request.recordingDigest = nil; request.holdAudio = false
    _ = try journal.enqueue(request); _ = try journal.begin(request.id)
    var prior = f.result; prior.receipt.completeness = .partial
    try journal.checkpoint(request.id, result: prior)
    try journal.fail(request.id, message: "First interruption")
    let relaunched = try TranscriptPreparationJournal(directory: folder)
    #expect(relaunched.retainsAudio(episode: request.episode))
    _ = try relaunched.begin(request.id)
    var shorter = prior
    shorter.document = TranscriptDocument(text: "Retained", words: [.init(text: "Retained", start: 1, end: 2)])
    try relaunched.checkpoint(request.id, result: shorter)
    try relaunched.fail(request.id, message: "Second interruption")
    let stillFurthest = try relaunched.draft(request.id)
    #expect(stillFurthest == prior)
    _ = try relaunched.begin(request.id)
    var changedRecording = prior
    changedRecording.receipt.recordingDigest = String(repeating: "b", count: 64)
    #expect(throws: TranscriptPreparationError.recordingChanged) {
      try relaunched.checkpoint(request.id, result: changedRecording)
    }
    var corrected = prior
    corrected.document = TranscriptDocument(text: "Corrected original words.", words: [
      .init(text: "Corrected original words.", start: 1, end: 4)])
    try relaunched.checkpoint(request.id, result: corrected)
    let sameCoverageCorrection = try relaunched.draft(request.id)
    #expect(sameCoverageCorrection == corrected)
    var caughtUp = prior
    caughtUp.document = TranscriptDocument(text: "Retained original words. More.", words: [
      .init(text: "Retained original words.", start: 1, end: 4), .init(text: "More.", start: 4, end: 5)])
    try relaunched.checkpoint(request.id, result: caughtUp)
    let latest = try relaunched.draft(request.id)
    #expect(latest == caughtUp)
    try relaunched.cancel(request.id)
    try relaunched.discardDraft(request.id)
    #expect(!relaunched.retainsAudio(episode: request.episode))
  }

  @Test func failedDurableCancellationKeepsRecoverableDraftAndAudioPin() throws {
    let f = try Fixture(); let folder = try directory()
    let backup = folder.appendingPathExtension("backup")
    defer {
      try? FileManager.default.removeItem(at: folder)
      try? FileManager.default.removeItem(at: backup)
    }
    let journal = try TranscriptPreparationJournal(directory: folder)
    var request = f.request; request.holdAudio = false
    _ = try journal.enqueue(request); _ = try journal.begin(request.id)
    var partial = f.result; partial.receipt.completeness = .partial
    try journal.checkpoint(request.id, result: partial)
    // Replace the journal's directory with a file to make an atomic metadata write fail.
    try FileManager.default.moveItem(at: folder, to: backup)
    try Data().write(to: folder)
    #expect(throws: (any Error).self) { try journal.cancel(request.id) }
    #expect(journal.record(request.id)?.state == .running)
    #expect(journal.retainsAudio(episode: request.episode))
    try FileManager.default.removeItem(at: folder)
    try FileManager.default.moveItem(at: backup, to: folder)
    let relaunched = try TranscriptPreparationJournal(directory: folder)
    try relaunched.recoverInterrupted()
    let retained = try relaunched.draft(request.id)
    #expect(retained == partial)
    #expect(relaunched.retainsAudio(episode: request.episode))
  }

  @Test func killAndRelaunchRecoverRunningAndPersistedReadyWithoutExecution() throws {
    let f = try Fixture(); let folder = try directory()
    defer { try? FileManager.default.removeItem(at: folder) }
    let journal = try TranscriptPreparationJournal(directory: folder)
    _ = try journal.enqueue(f.request); _ = try journal.begin(f.request.id)
    let relaunched = try TranscriptPreparationJournal(directory: folder)
    try relaunched.recoverInterrupted()
    #expect(relaunched.record(f.request.id)?.state == .interrupted)
    #expect(relaunched.record(f.request.id)?.attempts == 1)
    _ = try relaunched.begin(f.request.id)
    try relaunched.ready(f.request.id, result: f.result)
    try relaunched.reportFailure(f.request.id, message: "Source access is temporarily unavailable.")
    let readyLaunch = try TranscriptPreparationJournal(directory: folder)
    try readyLaunch.recoverInterrupted()
    let retained = try readyLaunch.result(f.request.id)
    #expect(retained == f.result)
    #expect(readyLaunch.record(f.request.id)?.state == .ready)
    #expect(readyLaunch.record(f.request.id)?.attempts == 2)
    #expect(readyLaunch.record(f.request.id)?.failure == "Source access is temporarily unavailable.")
    let committed = try f.phone.apply(request: f.request, result: retained)
    try readyLaunch.applied(f.request.id, revision: committed.revision)
    #expect(readyLaunch.record(f.request.id)?.failure == nil)
    #expect(readyLaunch.record(f.request.id)?.state == .applied)
  }

  @Test func resultWriteBeforeMetadataTransitionRecoversReady() throws {
    let f = try Fixture(); let folder = try directory()
    defer { try? FileManager.default.removeItem(at: folder) }
    let journal = try TranscriptPreparationJournal(directory: folder)
    _ = try journal.enqueue(f.request); _ = try journal.begin(f.request.id)
    try Canonical.encode(f.result).write(to: journal.resultFile(f.request.id), options: .atomic)
    let restart = try TranscriptPreparationJournal(directory: folder)
    try restart.recoverInterrupted()
    #expect(restart.record(f.request.id)?.state == .ready)
    let result = try restart.result(f.request.id)
    #expect(result == f.result)
  }

  @Test func commitThenCrashReplaysSameSignedRevision() throws {
    let f = try Fixture()
    let first = try f.phone.apply(request: f.request, result: f.result)
    let recovered = try f.phone.apply(request: f.request, result: f.result)
    #expect(recovered == first)
    let references = try SharedTranscriptService(replica: f.phone.replica).references()
    #expect(references.count == 1)
    var different = f.result
    different.document = TranscriptDocument(text: "Other source", words: nil)
    #expect(throws: TranscriptPreparationError.conflictingRequest) {
      try f.phone.apply(request: f.request, result: different)
    }
  }

  @Test func cancellationPreservesLateResultAndAudioUntilDeliberateRelease() throws {
    let f = try Fixture(); let folder = try directory()
    defer { try? FileManager.default.removeItem(at: folder) }
    let journal = try TranscriptPreparationJournal(directory: folder)
    _ = try journal.enqueue(f.request); _ = try journal.begin(f.request.id)
    try f.audio.write(to: journal.audioFile(f.request.id))
    try journal.cancel(f.request.id)
    try journal.ready(f.request.id, result: f.result)
    #expect(journal.record(f.request.id)?.state == .cancelled)
    #expect(journal.retainsAudio(episode: "episode"))
    #expect(throws: TranscriptPreparationError.cancelled) { try journal.applied(f.request.id, revision: "late") }
    #expect(throws: TranscriptPreparationError.notReady) { try journal.removeAppliedAudio(f.request.id) }
    try journal.releaseAudio(f.request.id); try journal.removeAppliedAudio(f.request.id)
    #expect(!journal.retainsAudio(episode: "episode"))
    let retained = try journal.result(f.request.id)
    #expect(retained == f.result)
  }

  @Test func failedClippingPinsAudioAndCompleteApplyReleasesOnlyAudio() throws {
    let f = try Fixture(); let folder = try directory()
    defer { try? FileManager.default.removeItem(at: folder) }
    let journal = try TranscriptPreparationJournal(directory: folder)
    _ = try journal.enqueue(f.request); _ = try journal.begin(f.request.id)
    try f.audio.write(to: journal.audioFile(f.request.id))
    try journal.fail(f.request.id, message: "No model")
    #expect(journal.retainsAudio(episode: "episode"))
    _ = try journal.begin(f.request.id); try journal.ready(f.request.id, result: f.result)
    try journal.applied(f.request.id, revision: "saved"); try journal.removeAppliedAudio(f.request.id)
    #expect(!journal.retainsAudio(episode: "episode"))
    #expect(FileManager.default.fileExists(atPath: journal.resultFile(f.request.id).path))
  }

  @Test func exactRecordingHashAndMalformedSourceReject() async throws {
    let f = try Fixture(); let folder = try directory()
    defer { try? FileManager.default.removeItem(at: folder) }
    let file = folder.appending(path: "audio")
    try f.audio.write(to: file)
    let digest = try await PodcastRecordingIdentity.digest(of: file)
    #expect(digest == Canonical.digest(f.audio))
    let journal = try TranscriptPreparationJournal(directory: folder)
    _ = try journal.enqueue(f.request)
    var changed = f.result
    changed.receipt.recordingDigest = Canonical.digest(Data("new recording".utf8))
    #expect(throws: TranscriptPreparationError.recordingChanged) { try journal.ready(f.request.id, result: changed) }
    changed.receipt.sourceURL = "file:///private/person/audio.mp3"
    #expect(throws: TranscriptPreparationError.invalidSource) { try changed.validate() }
  }

  @Test func rawPublisherProvenanceSurvivesCommitAndReplay() throws {
    let f = try Fixture()
    let raw = Data("WEBVTT\n\n00:00.000 --> 00:01.000\nOriginal".utf8)
    let result = TranscriptPreparationResult(document: TranscriptDocument(text: "Original", words: nil), source: "publisher",
      receipt: TranscriptSourceReceipt(sourceURL: "https://example.com/source.vtt", finalURL: "https://cdn.example.com/a.vtt",
        mediaType: "text/vtt", etag: "\"v1\"", lastModified: "Tue, 20 Oct 2026 12:00:00 GMT",
        parser: "TranscriptParser/1 vtt", language: "en", completeness: .unknown), raw: raw)
    let saved = try f.phone.apply(request: f.request, result: result)
    let savedReceipt = try f.phone.receipt(for: saved)
    let receipt = try #require(savedReceipt)
    let blob = try #require(receipt.raw)
    let retainedRaw = try f.phone.replica.blob(blob, in: Podcasts.namespace)
    #expect(retainedRaw == raw)
    #expect(blob.plain == Canonical.digest(raw))
    #expect(receipt.finalURL == "https://cdn.example.com/a.vtt")
    #expect(receipt.recordingDigest == nil)
    #expect(receipt.completeness == .unknown)
  }

  @Test func selectedMacRoundTripAndDuplicateDeliveryProduceOneTranscript() throws {
    let f = try Fixture(); let assignment = try f.assign()
    let again = try f.assign()
    #expect(again.revision == assignment.revision)
    let result = try f.mac.complete(assignment, result: f.result)
    let replay = try f.mac.complete(assignment, result: f.result)
    #expect(replay == result)
    let saved = try f.phone.accept(assignment, recordingDigest: Canonical.digest(f.audio))
    let acceptedAgain = try f.phone.accept(assignment, recordingDigest: Canonical.digest(f.audio))
    #expect(saved == acceptedAgain)
    let document = try SharedTranscriptService(replica: f.phone.replica).resolve(saved)
    #expect(document.text == f.result.document.text)
    let references = try SharedTranscriptService(replica: f.phone.replica).references()
    #expect(references.count == 1)
  }

  @Test func cancelledAndRevokedWorkerCannotInstallLateResults() throws {
    let f = try Fixture(); let assignment = try f.assign()
    _ = try f.mac.complete(assignment, result: f.result)
    try f.phone.cancel(assignment)
    #expect(throws: TranscriptPreparationError.cancelled) {
      try f.phone.accept(assignment, recordingDigest: Canonical.digest(f.audio))
    }
    let assignments = try f.phone.assignments()
    let cancelled = try #require(assignments.first)
    #expect(cancelled.result != nil)
    #expect(cancelled.cancelled)
    let other = try Fixture(); let pending = try other.assign()
    _ = try other.mac.complete(pending, result: other.result)
    try other.revokeWorker()
    #expect(throws: TranscriptPreparationError.noAccess) {
      try other.phone.accept(pending, recordingDigest: Canonical.digest(other.audio))
    }
  }

  @Test func wrongWorkerAndChangedRecordingCannotSupplyOldTimes() throws {
    let f = try Fixture(); let assignment = try f.assign()
    let stranger = TranscriptPreparationService(replica: Replica(store: f.store, identity: f.other))
    #expect(throws: TranscriptPreparationError.wrongWorker) { try stranger.complete(assignment, result: f.result) }
    _ = try f.mac.complete(assignment, result: f.result)
    let changed = Canonical.digest(Data("other recording".utf8))
    #expect(throws: TranscriptPreparationError.recordingChanged) {
      try f.phone.accept(assignment, recordingDigest: changed)
    }
    let references = try SharedTranscriptService(replica: f.phone.replica).references()
    #expect(references.isEmpty)
  }
  @Test func crossReplicaPhoneToMacResultSyncRetainsSearchableSignedText() async throws {
    let f = try Fixture()
    let assignment = try f.assign()
    let macStore = MemoryStore()
    _ = try await StoreSync(local: macStore, remote: LocalRemote(f.store)).run()
    let mac = TranscriptPreparationService(replica: Replica(store: macStore, identity: f.worker))
    let delivered = try mac.assignments()
    #expect(delivered.count == 1)
    _ = try mac.complete(assignment, result: f.result)
    let beforeSync = try f.phone.assignments()
    #expect(beforeSync.first?.result == nil)
    _ = try await StoreSync(local: f.store, remote: LocalRemote(macStore)).run()
    let saved = try f.phone.accept(assignment, recordingDigest: Canonical.digest(f.audio))
    let retained = try SharedTranscriptService(replica: f.phone.replica).resolve(saved)
    #expect(retained.text.localizedStandardContains("original words"))
    let receipt = try f.phone.receipt(for: saved)
    #expect(receipt?.recordingDigest == Canonical.digest(f.audio))
  }

  @Test func directSignedMalformedWorkerResultCannotClaimPublisherOrOtherLanguage() throws {
    for invalid in ["source", "language", "partial"] {
      let f = try Fixture(); let assignment = try f.assign()
      var result = f.result
      if invalid == "source" { result.source = "publisher" }
      if invalid == "language" { result.receipt.language = "fr_FR" }
      if invalid == "partial" { result.receipt.completeness = .partial }
      let blob = try f.mac.replica.putBlob(Canonical.encode(result), in: Podcasts.namespace)
      _ = try f.mac.replica.perform(Command(namespace: Podcasts.namespace, kind: TranscriptPreparationService.resultKind,
        payload: ["requestRevision": .string(assignment.revision), "result": blob.json]))
      #expect(throws: TranscriptPreparationError.recordingChanged) {
        try f.phone.accept(assignment, recordingDigest: Canonical.digest(f.audio))
      }
      let versions = try SharedTranscriptService(replica: f.phone.replica).references()
      #expect(versions.isEmpty)
    }
  }

  @Test func duplicateEncryptedResultsWithSamePlaintextAreOneSemanticResult() throws {
    let f = try Fixture(); let assignment = try f.assign()
    let bytes = try Canonical.encode(f.result)
    for _ in 0..<2 {
      let blob = try f.mac.replica.putBlob(bytes, in: Podcasts.namespace)
      _ = try f.mac.replica.perform(Command(namespace: Podcasts.namespace, kind: TranscriptPreparationService.resultKind,
        payload: ["requestRevision": .string(assignment.revision), "result": blob.json]))
    }
    let delivered = try f.phone.assignments()
    #expect(delivered.first?.result != nil)
    _ = try f.phone.accept(assignment, recordingDigest: Canonical.digest(f.audio))
    let versions = try SharedTranscriptService(replica: f.phone.replica).references()
    #expect(versions.count == 1)
  }

  @Test func futureVersionCancellationAndResultAreNotInterpretedAsV1() throws {
    let f = try Fixture(); let assignment = try f.assign()
    _ = try f.phone.replica.perform(Command(namespace: Podcasts.namespace, kind: TranscriptPreparationService.cancelKind,
      v: 2, payload: ["requestRevision": .string(assignment.revision)]))
    let blob = try f.mac.replica.putBlob(Canonical.encode(f.result), in: Podcasts.namespace)
    _ = try f.mac.replica.perform(Command(namespace: Podcasts.namespace, kind: TranscriptPreparationService.resultKind,
      v: 2, payload: ["requestRevision": .string(assignment.revision), "result": blob.json]))
    let delivered = try f.phone.assignments()
    #expect(delivered.first?.cancelled == false)
    #expect(delivered.first?.result == nil)
  }

  @Test(arguments: [false, true])
  func workerCannotIntroduceOrReplaceAssignedRecordingSource(hasAssignedSource: Bool) throws {
    let f = try Fixture()
    let original = TranscriptRecordingSource(feed: "https://example.org/feed", guid: "episode",
      enclosure: "https://example.org/audio.mp3", byteLength: Int64(f.audio.count))
    var request = f.request
    request.recordingSource = hasAssignedSource ? original : nil
    let audio = try f.phone.replica.putBlob(f.audio, in: Podcasts.namespace)
    let assignment = try f.phone.request(request, audio: audio, worker: f.worker.id)
    var result = f.result
    result.receipt.recordingSource = TranscriptRecordingSource(feed: original.feed, guid: original.guid,
      enclosure: "https://example.org/different.mp3", byteLength: original.byteLength)
    #expect(throws: TranscriptPreparationError.recordingChanged) {
      try f.mac.complete(assignment, result: result)
    }
    // A signed worker write that bypasses complete must still fail requester acceptance.
    let blob = try f.mac.replica.putBlob(Canonical.encode(result), in: Podcasts.namespace)
    _ = try f.mac.replica.perform(Command(namespace: Podcasts.namespace, kind: TranscriptPreparationService.resultKind,
      payload: ["requestRevision": .string(assignment.revision), "result": blob.json]))
    #expect(throws: TranscriptPreparationError.recordingChanged) {
      try f.phone.accept(assignment, recordingDigest: Canonical.digest(f.audio))
    }
    let references = try SharedTranscriptService(replica: f.phone.replica).references()
    #expect(references.isEmpty)
  }

  @Test(arguments: [false, true])
  func workerMayOmitLegacySourceOrReturnAssignedSource(returnsSource: Bool) throws {
    let f = try Fixture()
    let source = TranscriptRecordingSource(feed: "https://example.org/feed", guid: "episode",
      enclosure: "https://example.org/audio.mp3", byteLength: Int64(f.audio.count))
    var request = f.request
    request.recordingSource = source
    let audio = try f.phone.replica.putBlob(f.audio, in: Podcasts.namespace)
    let assignment = try f.phone.request(request, audio: audio, worker: f.worker.id)
    var result = f.result
    result.receipt.recordingSource = returnsSource ? source : nil
    _ = try f.mac.complete(assignment, result: result)
    let saved = try f.phone.accept(assignment, recordingDigest: Canonical.digest(f.audio))
    let receipt = try f.phone.receipt(for: saved)
    #expect(receipt?.recordingSource == result.receipt.recordingSource)
  }

}
