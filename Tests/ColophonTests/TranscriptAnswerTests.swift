import ColophonAuthority
import ColophonCore
import ColophonListening
import ColophonReplica
import ColophonStore
import Foundation
import Testing

struct TranscriptAnswerTests {
  private struct Fixture {
    let store = MemoryStore()
    let person = SoftwareIdentity()
    let root = SoftwareIdentity()
    let agent = SoftwareIdentity()
    let holder: AuthorityHolder
    let replica: Replica
    init() throws {
      let (holder, _) = try AuthorityHolder.create(in: store, label: "Answers", root: root,
        firstMember: person.publicIdentity, memberLabel: "Phone", role: .app,
        custody: .software, namespaces: [Podcasts.namespace])
      try holder.admit(agent.publicIdentity, label: "Research agent", role: .agent,
        custody: .software, namespaces: [Podcasts.namespace], write: true)
      self.holder = holder
      replica = Replica(store: store, identity: person)
    }
    func anchor(_ text: String, episode: String) throws -> TranscriptNoteAnchor {
      let op = try replica.saveTranscript(TranscriptDocument(text: text, words: nil), episode: episode,
        show: "show", source: "publisher", language: "en")
      let reference = SharedTranscriptReference(libraryID: try replica.authority().libraryID,
        episode: episode, show: "show", revision: op.id, blob: try #require(BlobRef(json: op.payload["blob"])))
      return TranscriptNoteAnchor(reference: reference, startUTF16: 0, lengthUTF16: text.utf16.count, quote: text)
    }
  }

  @Test func multiSourceClaimsPersistReplayAndStayPinnedAcrossReplacement() throws {
    let f = try Fixture()
    let first = try f.anchor("🐋 The harbour is quiet.", episode: "one")
    let second = try f.anchor("The ocean is loud.", episode: "two")
    let claims = [TranscriptAnswerClaim(text: "The sources disagree about quiet.", citations: [first, second]),
      TranscriptAnswerClaim(text: "The harbour source mentions quiet.", citations: [first])]
    let service = TranscriptAnswerService(replica: f.replica)
    let saved = try service.save(question: "Compare the sources.", claims: claims, commandID: "keep")
    let replay = try service.save(question: "Compare the sources.", claims: claims, commandID: "keep")
    #expect(saved == replay)
    #expect(saved.claims == claims)
    #expect(saved.authorID == f.person.id)
    #expect(saved.origin == .onDevice)
    #expect(saved.status == .verified)
    _ = try f.anchor("A revised transcript.", episode: "one")
    let restoredValue = try service.record(revision: saved.id)
    let restored = try #require(restoredValue)
    #expect(restored.claims == claims)
    #expect(restored.status == .verified)
    #expect(throws: TranscriptAnswerError.commandIDConflict) {
      try service.save(question: "A different question.", claims: claims, commandID: "keep")
    }
  }

  @Test func forgedOffsetsRejectedAndRealAgentSignerSurvivesSync() async throws {
    let f = try Fixture()
    let anchor = try f.anchor("Exact evidence.", episode: "one")
    let bad = TranscriptNoteAnchor(reference: anchor.reference, startUTF16: 1,
      lengthUTF16: anchor.lengthUTF16, quote: anchor.quote)
    let service = TranscriptAnswerService(replica: f.replica)
    #expect(throws: SharedTranscriptError.wrongCitation) {
      try service.save(question: "Why?", claims: [.init(text: "Claim.", citations: [bad])], commandID: "bad")
    }
    let agentService = TranscriptAnswerService(replica: Replica(store: f.store, identity: f.agent))
    let saved = try agentService.save(question: "Why?", claims: [.init(text: "Claim.", citations: [anchor])],
      commandID: "agent")
    #expect(saved.authorID == f.agent.id)
    #expect(saved.authorRole == .agent)
    #expect(saved.origin == .agent)
    let remote = MemoryStore()
    _ = try await StoreSync(local: remote, remote: LocalRemote(f.store)).run()
    let syncedValue = try TranscriptAnswerService(replica: Replica(store: remote, identity: f.person))
      .record(revision: saved.id)
    let synced = try #require(syncedValue)
    #expect(synced.claims == saved.claims)
    #expect(synced.authorLabel == "Research agent")
  }

  @Test func missingOneBlobPreservesAllCitationsAndArrivalPromotesRecord() throws {
    let f = try Fixture()
    let first = try f.anchor("First source.", episode: "one")
    let second = try f.anchor("Second source.", episode: "two")
    let claims = [TranscriptAnswerClaim(text: "Both sources.", citations: [first, second])]
    let saved = try TranscriptAnswerService(replica: f.replica).save(question: "Both?", claims: claims,
      commandID: "saved")
    let partial = MemoryStore()
    let omitted = LibraryPath.blob(second.reference.blob.digest)
    for (path, data) in f.store.snapshot where path != omitted { try partial.create(path, data) }
    let service = TranscriptAnswerService(replica: Replica(store: partial, identity: f.person))
    let pendingValue = try service.record(revision: saved.id)
    let pending = try #require(pendingValue)
    #expect(pending.status == .pendingSource)
    #expect(pending.claims == claims)
    let storedBytes = try f.store.read(omitted)
    let bytes = try #require(storedBytes)
    try partial.create(omitted, bytes)
    let readyValue = try service.record(revision: saved.id)
    let ready = try #require(readyValue)
    #expect(ready.status == .verified)
    #expect(ready.claims == claims)
  }

  @Test func signedConflictingReuseIsVisibleAndCurrentRevocationDeniesRead() throws {
    let f = try Fixture()
    let anchor = try f.anchor("Exact evidence.", episode: "one")
    let service = TranscriptAnswerService(replica: f.replica)
    let saved = try service.save(question: "First?", claims: [.init(text: "Claim.", citations: [anchor])],
      commandID: "same")
    let claims: [TranscriptAnswerClaim] = [.init(text: "Different claim.", citations: [anchor])]
    var body: [String: JSONValue] = ["libraryID": .string(saved.libraryID), "question": .string("Second?"),
      "claims": try Canonical.decode(JSONValue.self, from: Canonical.encode(claims))]
    let digest = Canonical.digest(try Canonical.encode(body))
    body["commandID"] = .string("same")
    body["commandDigest"] = .string(digest)
    try f.replica.perform(Command(namespace: Podcasts.namespace, kind: TranscriptAnswerService.saveKind, payload: body))
    let collection = try service.collection()
    #expect(collection.records.count == 2)
    #expect(collection.records.allSatisfy { $0.status == .conflict })
    try f.holder.revoke(f.person.id)
    #expect(throws: TranscriptAnswerError.noCurrentAccess) { try service.collection() }
  }
}
