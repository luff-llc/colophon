import ColophonAuthority
import ColophonCore
import ColophonListening
import ColophonReplica
import ColophonStore
import Foundation
import Testing

struct TranscriptQuestionTests {
  private struct Fixture {
    let store = MemoryStore()
    let root = SoftwareIdentity()
    let phone = SoftwareIdentity()
    let agent = SoftwareIdentity()
    let otherAgent = SoftwareIdentity()
    let holder: AuthorityHolder
    let replica: Replica
    let now = Date(timeIntervalSince1970: 2_000_000_000)

    init() throws {
      let (holder, _) = try AuthorityHolder.create(in: store, label: "Questions", root: root,
        firstMember: phone.publicIdentity, memberLabel: "Phone", role: .app,
        custody: .software, namespaces: [Podcasts.namespace])
      try holder.admit(agent.publicIdentity, label: "Selected researcher", role: .agent,
        custody: .software, namespaces: [Podcasts.namespace], write: true)
      try holder.admit(otherAgent.publicIdentity, label: "Other researcher", role: .agent,
        custody: .software, namespaces: [Podcasts.namespace], write: true)
      self.holder = holder
      replica = Replica(store: store, identity: phone)
    }
    var service: TranscriptQuestionService {
      TranscriptQuestionService(replica: replica, now: { now })
    }
    var agentService: TranscriptQuestionService {
      TranscriptQuestionService(replica: Replica(store: store, identity: agent), now: { now })
    }
    func anchor(_ text: String, episode: String = "episode") throws -> TranscriptNoteAnchor {
      let op = try replica.saveTranscript(TranscriptDocument(text: text, words: nil), episode: episode,
        show: "show", source: "publisher", language: "en")
      let ref = SharedTranscriptReference(libraryID: try replica.authority().libraryID, episode: episode,
        show: "show", revision: op.id, blob: try #require(BlobRef(json: op.payload["blob"])))
      return TranscriptNoteAnchor(reference: ref, startUTF16: 0, lengthUTF16: text.utf16.count, quote: text)
    }
    func request(_ scope: [TranscriptNoteAnchor]) throws -> TranscriptQuestionRequest {
      try service.request(question: "Compare this evidence.", scope: scope, targetAgentID: agent.id,
        expires: now.addingTimeInterval(3_600), commandID: "question")
    }
    func sign(kind: String, body: [String: JSONValue], commandID: String, identity: SoftwareIdentity) throws {
      var payload = body
      payload["commandDigest"] = .string(Canonical.digest(try Canonical.encode(body)))
      payload["commandID"] = .string(commandID)
      try Replica(store: store, identity: identity).perform(Command(namespace: Podcasts.namespace, kind: kind, payload: payload))
    }
  }

  @Test func exactScopePacketAnswerAdmissionAndReplaySurviveExpiryAndSync() async throws {
    let f = try Fixture()
    let first = try f.anchor("🐋 The harbour is quiet.", episode: "one")
    let second = try f.anchor("The ocean is loud.", episode: "two")
    let request = try f.request([first, second])
    let replay = try f.request([first, second])
    #expect(request == replay)
    let packet = try f.agentService.packet(requestRevision: request.id)
    #expect(packet.passages == request.scope)
    #expect(packet.request.targetAgentID == f.agent.id)
    let claims = [TranscriptAnswerClaim(text: "These sources contrast.", citations: [first, second])]
    let response = try f.agentService.respond(requestRevision: request.id, claims: claims, commandID: "reply")
    let repeated = try f.agentService.respond(requestRevision: request.id, claims: claims, commandID: "reply")
    #expect(response == repeated)
    let pending = try f.service.state(revision: request.id)
    #expect(pending?.status == .awaitingReview)
    let admitted = try f.service.admit(responseRevision: response.id, commandID: "admit")
    #expect(admitted.admissionRevision != nil)
    #expect(admitted.agentID == f.agent.id)
    let later = TranscriptQuestionService(replica: f.replica, now: { f.now.addingTimeInterval(7_200) })
    let afterExpiry = try later.state(revision: request.id)
    #expect(afterExpiry?.status == .answered)
    let admittedReplay = try later.admit(responseRevision: response.id, commandID: "admit")
    #expect(admittedReplay == admitted)
    let requestReplay = try later.request(question: request.question, scope: request.scope,
      targetAgentID: request.targetAgentID, expires: request.expires, commandID: request.commandID)
    #expect(requestReplay == request)
    let laterAgent = TranscriptQuestionService(replica: Replica(store: f.store, identity: f.agent),
      now: { f.now.addingTimeInterval(7_200) })
    let responseReplay = try laterAgent.respond(requestRevision: request.id, claims: claims, commandID: "reply")
    #expect(responseReplay.id == response.id)
    #expect(throws: TranscriptQuestionError.expired) { try later.packet(requestRevision: request.id) }
    let remote = MemoryStore()
    _ = try await StoreSync(local: remote, remote: LocalRemote(f.store)).run()
    let restored = try TranscriptQuestionService(replica: Replica(store: remote, identity: f.phone),
      now: { f.now.addingTimeInterval(7_200) }).state(revision: request.id)
    #expect(restored?.responses.first?.claims == claims)
    #expect(restored?.responses.first?.agentLabel == "Selected researcher")
    #expect(restored?.status == .answered)
  }

  @Test func unselectedAgentAndScopeExpansionCannotUseBroker() throws {
    let f = try Fixture()
    let allowed = try f.anchor("Allowed passage.", episode: "one")
    let excluded = try f.anchor("Excluded passage.", episode: "two")
    let request = try f.request([allowed])
    let other = TranscriptQuestionService(replica: Replica(store: f.store, identity: f.otherAgent), now: { f.now })
    #expect(throws: TranscriptQuestionError.wrongAgent) { try other.packet(requestRevision: request.id) }
    #expect(throws: TranscriptQuestionError.wrongAgent) {
      try other.respond(requestRevision: request.id, claims: [.init(text: "No.", citations: [allowed])], commandID: "wrong")
    }
    #expect(throws: TranscriptQuestionError.outsideScope) {
      try f.agentService.respond(requestRevision: request.id,
        claims: [.init(text: "Wrong scope.", citations: [excluded])], commandID: "expanded")
    }
    let fabricated = TranscriptNoteAnchor(reference: allowed.reference, startUTF16: 0, lengthUTF16: 6, quote: "forged")
    #expect(throws: TranscriptQuestionError.outsideScope) {
      try f.agentService.respond(requestRevision: request.id,
        claims: [.init(text: "Fake quote.", citations: [fabricated])], commandID: "forged")
    }
    let packet = try f.agentService.packet(requestRevision: request.id)
    #expect(packet.passages.count == 1)
    #expect(packet.passages.first == allowed)
  }

  @Test func cancellationAndDeadlineBlockFreshWorkButPreserveOriginalEvidence() throws {
    let f = try Fixture()
    let anchor = try f.anchor("Evidence.")
    let request = try f.request([anchor])
    let response = try f.agentService.respond(requestRevision: request.id,
      claims: [.init(text: "Claim.", citations: [anchor])], commandID: "reply")
    let later = TranscriptQuestionService(replica: f.replica, now: { f.now.addingTimeInterval(7_200) })
    #expect(throws: TranscriptQuestionError.expired) { try later.admit(responseRevision: response.id, commandID: "late") }
    let expired = try later.state(revision: request.id)
    #expect(expired?.status == .expired)
    #expect(expired?.responses.first?.claims.first?.citations.first == anchor)
    try f.service.cancel(requestRevision: request.id, commandID: "cancel")
    try f.service.cancel(requestRevision: request.id, commandID: "cancel")
    let cancelled = try f.service.state(revision: request.id)
    #expect(cancelled?.status == .cancelled)
    #expect(cancelled?.responses.count == 1)
    #expect(throws: TranscriptQuestionError.cancelled) { try f.agentService.packet(requestRevision: request.id) }
    #expect(throws: TranscriptQuestionError.cancelled) {
      try f.service.admit(responseRevision: response.id, commandID: "after-cancel")
    }
  }

  @Test func revocationAndMissingBlobStopDisclosureAndArrivalRecovers() throws {
    let f = try Fixture()
    let anchor = try f.anchor("Evidence.")
    let request = try f.request([anchor])
    let partial = MemoryStore()
    let omitted = LibraryPath.blob(anchor.reference.blob.digest)
    for (path, data) in f.store.snapshot where path != omitted { try partial.create(path, data) }
    let service = TranscriptQuestionService(replica: Replica(store: partial, identity: f.phone), now: { f.now })
    let missing = try service.state(revision: request.id)
    #expect(missing?.status == .sourcePending)
    #expect(throws: TranscriptQuestionError.missingSource) { try service.packet(requestRevision: request.id) }
    let storedBytes = try f.store.read(omitted)
    let bytes = try #require(storedBytes)
    try partial.create(omitted, bytes)
    let packet = try service.packet(requestRevision: request.id)
    #expect(packet.passages == request.scope)
    try f.holder.revoke(f.agent.id)
    let revoked = try f.service.state(revision: request.id)
    #expect(revoked?.status == .accessUnavailable)
    #expect(throws: TranscriptQuestionError.noCurrentAccess) { try f.service.packet(requestRevision: request.id) }
  }

  @Test func expiredMissingSourcesDoNotConsumePendingQuestionQuota() throws {
    let f = try Fixture()
    let missingAnchor = try f.anchor("Evidence that has not synced.", episode: "missing")
    let retainedAnchor = try f.anchor("Available evidence.", episode: "available")
    var requests: [TranscriptQuestionRequest] = []
    for index in 0..<TranscriptQuestionService.maximumPending {
      let request = try f.service.request(question: "Compare this evidence.", scope: [missingAnchor],
        targetAgentID: f.agent.id, expires: f.now.addingTimeInterval(3_600), commandID: "pending-\(index)")
      requests.append(request)
    }
    let partial = MemoryStore()
    let omitted = LibraryPath.blob(missingAnchor.reference.blob.digest)
    for (path, data) in f.store.snapshot where path != omitted { try partial.create(path, data) }
    let replica = Replica(store: partial, identity: f.phone)
    let beforeExpiry = TranscriptQuestionService(replica: replica, now: { f.now })
    let pending = try beforeExpiry.states()
    #expect(pending.count == TranscriptQuestionService.maximumPending)
    #expect(pending.allSatisfy { $0.status == .sourcePending })
    #expect(throws: TranscriptQuestionError.tooManyPending) {
      try beforeExpiry.request(question: "A new question.", scope: [retainedAnchor], targetAgentID: f.agent.id,
        expires: f.now.addingTimeInterval(3_600), commandID: "new-question")
    }
    let later = TranscriptQuestionService(replica: replica, now: { f.now.addingTimeInterval(7_200) })
    let expired = try later.states()
    #expect(expired.allSatisfy { $0.status == .expired && $0.sourceReady == false })
    let first = try #require(requests.first)
    #expect(throws: TranscriptQuestionError.expired) { try later.packet(requestRevision: first.id) }
    let fresh = try later.request(question: "A new question.", scope: [retainedAnchor], targetAgentID: f.agent.id,
      expires: f.now.addingTimeInterval(10_800), commandID: "new-question")
    let freshState = try later.state(revision: fresh.id)
    #expect(freshState?.status == .queued)
  }

  @Test func competingOfflineResponsesAndChangedCommandReuseRemainConflicts() throws {
    let f = try Fixture()
    let anchor = try f.anchor("Evidence.")
    let request = try f.request([anchor])
    _ = try f.agentService.respond(requestRevision: request.id,
      claims: [.init(text: "First.", citations: [anchor])], commandID: "reply")
    let secondClaims = [TranscriptAnswerClaim(text: "Competing.", citations: [anchor])]
    let body: [String: JSONValue] = ["libraryID": .string(request.libraryID),
      "requestRevision": .string(request.id), "scopeDigest": .string(request.scopeDigest),
      "claims": try Canonical.decode(JSONValue.self, from: Canonical.encode(secondClaims))]
    try f.sign(kind: TranscriptQuestionService.responseKind, body: body, commandID: "offline", identity: f.agent)
    let conflicted = try f.service.state(revision: request.id)
    #expect(conflicted?.status == .conflict)
    #expect(conflicted?.responses.count == 2)
    #expect(throws: TranscriptQuestionError.conflict) { try f.service.packet(requestRevision: request.id) }
    #expect(throws: TranscriptQuestionError.commandIDConflict) {
      try f.service.request(question: "Different question.", scope: [anchor], targetAgentID: f.agent.id,
        expires: f.now.addingTimeInterval(3_600), commandID: "question")
    }
  }
}
