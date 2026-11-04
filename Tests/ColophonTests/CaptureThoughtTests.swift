import ColophonAuthority
import ColophonCore
import ColophonListening
import ColophonReplica
import ColophonStore
import Foundation
import Testing

@Suite struct CaptureThoughtTests {
  private struct Fixture {
    let store = MemoryStore()
    let root = SoftwareIdentity()
    let phone = SoftwareIdentity()
    let agent = SoftwareIdentity()
    let other = SoftwareIdentity()

    init() throws {
      let (holder, _) = try AuthorityHolder.create(in: store, label: "Capture fixture", root: root,
        firstMember: phone.publicIdentity, memberLabel: "Taupe", role: .app,
        custody: .software, namespaces: [Podcasts.namespace])
      try holder.admit(agent.publicIdentity, label: "Selected agent", role: .agent, custody: .software,
        namespaces: [Podcasts.namespace], write: true)
      try holder.admit(other.publicIdentity, label: "Other agent", role: .agent, custody: .software,
        namespaces: [Podcasts.namespace], write: true)
    }

    var phoneReplica: Replica { Replica(store: store, identity: phone) }
    var phoneService: CaptureThoughtService { CaptureThoughtService(replica: phoneReplica) }
    var agentService: CaptureThoughtService {
      CaptureThoughtService(replica: Replica(store: store, identity: agent))
    }
    var otherService: CaptureThoughtService {
      CaptureThoughtService(replica: Replica(store: store, identity: other))
    }

    func anchoredSnapshot() throws -> CaptureThoughtSnapshot {
      let text = "Before 🐋 the harbour. After."
      try phoneReplica.saveTranscript(TranscriptDocument(text: text, words: nil), episode: "episode",
        show: "show", source: "publisher", language: "en")
      let savedReference = try SharedTranscriptService(replica: phoneReplica).reference(episode: "episode")
      let reference = try #require(savedReference)
      let quote = "the harbour"
      let range = try #require(text.range(of: quote))
      let offset = NSRange(range, in: text)
      let anchor = TranscriptNoteAnchor(reference: reference, startUTF16: offset.location,
        lengthUTF16: offset.length, quote: quote)
      return CaptureThoughtSnapshot(episode: "episode", show: "show", seconds: 12.5,
        anchor: anchor, surroundingText: text)
    }
  }

  @Test func textCaptureIsOneSignedNoteWithExactSourceAndStableReplay() throws {
    let f = try Fixture()
    let snapshot = try f.anchoredSnapshot()
    let first = try f.phoneService.save(snapshot: snapshot, input: .text("Keep this thought."),
      requestID: "capture-1")
    let again = try f.phoneService.save(snapshot: snapshot, input: .text("Keep this thought."),
      requestID: "capture-1")
    #expect(first == again)
    #expect(first.noteID != first.requestID)
    #expect(first.snapshot.anchor == snapshot.anchor)
    #expect(first.targetAgentID == nil)
    #expect(try f.phoneService.state(requestID: "capture-1").status == .queued)
    #expect(try f.phoneService.state(noteID: first.noteID).request.revision == first.revision)
    let note = try #require(f.phoneReplica.state(of: Podcasts.self).notes[first.noteID])
    #expect(note.revision == first.revision)
    #expect(note.text == "Keep this thought.")
    #expect(note.authorID == f.phone.id)
    #expect(TranscriptNoteService(replica: f.phoneReplica).status(of: note) == .verified)
    #expect(throws: CaptureThoughtError.commandIDConflict) {
      try f.phoneService.save(snapshot: snapshot, input: .text("Changed thought."), requestID: "capture-1")
    }
  }

  @Test func voiceCaptureRetainsOriginalBytesInSealedBlob() throws {
    let f = try Fixture()
    let snapshot = CaptureThoughtSnapshot(episode: "episode", show: "show", seconds: 4.25)
    let original = Data("original voice bytes".utf8)
    let saved = try f.phoneService.save(snapshot: snapshot,
      input: .voice(data: original, mimeType: "audio/x-caf", text: "My typed thought too"), requestID: "voice-1")
    let blob = try #require(saved.voice)
    #expect(saved.text == "My typed thought too")
    #expect(saved.voiceMimeType == "audio/x-caf")
    #expect(blob.plain == Canonical.digest(original))
    #expect(try f.phoneReplica.blob(blob, in: Podcasts.namespace) == original)
    #expect(try f.phoneService.state(requestID: "voice-1").status == .queued)
    let note = try #require(f.phoneReplica.state(of: Podcasts.self).notes[saved.noteID])
    #expect(note.revision == saved.revision)
    #expect(note.text == "My typed thought too")
  }

  @Test func ordinaryNoteWithScopedCaptureIDCannotBeShadowed() throws {
    let f = try Fixture()
    let requestID = "collision"
    let noteID = "\(f.phone.id.utf8.count):\(f.phone.id)\(requestID.utf8.count):\(requestID)"
    _ = try f.phoneReplica.perform(Podcasts.note(noteID, episode: "episode", show: "show",
      seconds: 1, text: "Existing note"))
    let snapshot = CaptureThoughtSnapshot(episode: "episode", show: "show", seconds: 1)
    #expect(throws: CaptureThoughtError.commandIDConflict) {
      try f.phoneService.save(snapshot: snapshot, input: .text("New capture"), requestID: requestID)
    }
    let note = try #require(f.phoneReplica.state(of: Podcasts.self).notes[noteID])
    #expect(note.text == "Existing note")
  }

  @Test func conflictingSignedReuseMarksOnlyItsCapture() throws {
    let f = try Fixture()
    let snapshot = CaptureThoughtSnapshot(episode: "episode", show: "show", seconds: 1)
    let conflicted = try f.phoneService.save(snapshot: snapshot, input: .text("First"), requestID: "reuse")
    let unaffected = try f.phoneService.save(snapshot: snapshot, input: .text("Other"), requestID: "other")
    let entries = try f.phoneReplica.read(Podcasts.namespace).admitted
    let candidate = entries.first { $0.operation.id == conflicted.revision }?.operation
    let firstOperation = try #require(candidate)
    var payload = firstOperation.payload
    var capture = try #require(payload["captureThought"]?.object)
    let body: [String: JSONValue] = [
      "requestID": .string("reuse"), "episode": .string("episode"), "show": .string("show"),
      "seconds": .number(1), "anchor": .null, "surroundingText": .string(""),
      "originalText": .string("Changed"), "voicePlain": .null,
      "voiceMimeType": .null, "targetAgentID": .null
    ]
    capture["originalText"] = .string("Changed")
    capture["digest"] = .string(Canonical.digest(try Canonical.encode(body)))
    payload["captureThought"] = .object(capture)
    payload["text"] = .string("Changed")
    _ = try f.phoneReplica.perform(Command(namespace: Podcasts.namespace,
      kind: Podcasts.ContentKind.addNote, payload: payload))
    let states = try f.phoneService.states()
    #expect(states[conflicted.noteID]?.status == .conflict)
    #expect(states[unaffected.noteID]?.status == .queued)
    #expect(throws: CaptureThoughtError.commandIDConflict) {
      try f.phoneService.save(snapshot: snapshot, input: .text("First"), requestID: "reuse")
    }
  }

  @Test func selectedAgentResponseIsAttributedCorrelatedAndIdempotent() throws {
    let f = try Fixture()
    let request = try f.phoneService.save(snapshot: CaptureThoughtSnapshot(episode: "episode", show: "show",
      seconds: 8, surroundingText: "A short surrounding passage."), input: .text("Why?"),
      targetAgentID: f.agent.id, requestID: "question")
    #expect(try f.phoneService.state(requestID: "question").status == .awaitingAgent)
    #expect(throws: CaptureThoughtError.wrongAgent) {
      try f.otherService.respond(requestID: "question", requestRevision: request.revision,
        text: "Impersonation", commandID: "other-1")
    }
    #expect(throws: CaptureThoughtError.staleRequest) {
      try f.agentService.respond(requestID: "question", requestRevision: "wrong-revision",
        text: "Stale", commandID: "stale-1")
    }
    let answer = try f.agentService.respond(requestID: "question", requestRevision: request.revision,
      text: "Because of the earlier point.", commandID: "answer-1")
    let replay = try f.agentService.respond(requestID: "question", requestRevision: request.revision,
      text: "Because of the earlier point.", commandID: "answer-1")
    #expect(answer == replay)
    #expect(answer.agentID == f.agent.id)
    #expect(answer.agentLabel == "Selected agent")
    let state = try f.phoneService.state(requestID: "question")
    #expect(state.response == answer)
    #expect(state.status == .responded)
    #expect(state.request.noteID == request.noteID)
    #expect(throws: CaptureThoughtError.commandIDConflict) {
      try f.agentService.respond(requestID: "question", requestRevision: request.revision,
        text: "Conflicting answer.", commandID: "answer-1")
    }
  }

  @Test func cancellationAndRevocationRejectLaterCallbacks() throws {
    let f = try Fixture()
    let request = try f.phoneService.save(snapshot: CaptureThoughtSnapshot(episode: "episode", show: "show", seconds: 1),
      input: .text("Question"), targetAgentID: f.agent.id, requestID: "cancelled")
    try f.phoneService.cancel(requestID: request.requestID, requestRevision: request.revision)
    #expect(try f.phoneService.state(requestID: "cancelled").status == .cancelled)
    #expect(throws: CaptureThoughtError.cancelled) {
      try f.agentService.respond(requestID: "cancelled", requestRevision: request.revision,
        text: "Too late", commandID: "late")
    }
    let second = try f.phoneService.save(snapshot: CaptureThoughtSnapshot(episode: "episode", show: "show", seconds: 2),
      input: .text("Another"), targetAgentID: f.agent.id, requestID: "revoked")
    try AuthorityHolder(log: AuthorityLog(store: f.store), root: f.root).revoke(f.agent.id)
    #expect(throws: CaptureThoughtError.noCurrentAccess) {
      try f.agentService.respond(requestID: "revoked", requestRevision: second.revision,
        text: "No access", commandID: "revoked-answer")
    }
  }

  @Test func missingPinnedSourceKeepsSignedRequestVisibleButBlocksResponse() throws {
    let f = try Fixture()
    let snapshot = try f.anchoredSnapshot()
    let request = try f.phoneService.save(snapshot: snapshot, input: .text("Remember this"),
      targetAgentID: f.agent.id, requestID: "pending-source")
    let missing = try #require(snapshot.anchor?.reference.blob)
    let partial = MemoryStore()
    for (path, bytes) in f.store.snapshot where path != LibraryPath.blob(missing.digest) {
      try partial.create(path, bytes)
    }
    let local = CaptureThoughtService(replica: Replica(store: partial, identity: f.phone))
    let state = try local.state(noteID: request.noteID, requestRevision: request.revision)
    #expect(state.request == request)
    #expect(state.status == .awaitingAgent)
    #expect(state.sourceReady == false)
    let agent = CaptureThoughtService(replica: Replica(store: partial, identity: f.agent))
    #expect(throws: CaptureThoughtError.missingSource) {
      try agent.respond(requestID: request.requestID, requestRevision: request.revision,
        text: "Premature", commandID: "no-source")
    }
  }

  @Test func excludedSignedCallbackDoesNotAttachAfterRevocation() throws {
    let f = try Fixture()
    let request = try f.phoneService.save(snapshot: CaptureThoughtSnapshot(episode: "episode", show: "show", seconds: 3),
      input: .text("Question"), targetAgentID: f.agent.id, requestID: "exclude-response")
    _ = try f.agentService.respond(requestID: request.requestID, requestRevision: request.revision,
      text: "Temporary answer", commandID: "answer")
    try AuthorityHolder(log: AuthorityLog(store: f.store), root: f.root).revoke(f.agent.id, seen: [])
    let state = try f.phoneService.state(noteID: request.noteID)
    #expect(state.response == nil)
    #expect(state.status == .held)
  }
}
