import ColophonAuthority
import ColophonCore
import ColophonListening
import ColophonReplica
import ColophonStore
import Testing

@Suite struct SharedTranscriptTests {
  private struct Fixture {
    let phoneStore = MemoryStore()
    let laterStore = MemoryStore()
    let root = SoftwareIdentity()
    let person = SoftwareIdentity()
    let later = SoftwareIdentity()
    let agent = SoftwareIdentity()
    let otherAgent = SoftwareIdentity()
    let notesOnly = SoftwareIdentity()
    let expired = SoftwareIdentity()

    init() throws {
      let (holder, _) = try AuthorityHolder.create(in: phoneStore, label: "Shared transcript fixture",
        root: root, firstMember: person.publicIdentity, memberLabel: "Taupe phone",
        role: .app, custody: .software, namespaces: [Podcasts.namespace, "notes"])
      try holder.admit(later.publicIdentity, label: "Later iPad", role: .app, custody: .software,
        namespaces: [Podcasts.namespace], write: true)
      try holder.admit(agent.publicIdentity, label: "Context agent", role: .agent, custody: .software,
        namespaces: [Podcasts.namespace], write: true)
      try holder.admit(otherAgent.publicIdentity, label: "Other agent", role: .agent, custody: .software,
        namespaces: [Podcasts.namespace], write: true)
      try holder.admit(notesOnly.publicIdentity, label: "Notes-only", role: .app, custody: .software,
        namespaces: ["notes"], write: true)
      try holder.admit(expired.publicIdentity, label: "Expired", role: .app, custody: .software,
        namespaces: [Podcasts.namespace], write: true, expires: .distantPast)
    }

    var taupe: SharedTranscriptService { SharedTranscriptService(replica: Replica(store: phoneStore, identity: person)) }
    var agentService: SharedTranscriptService { SharedTranscriptService(replica: Replica(store: phoneStore, identity: agent)) }
    var laterService: SharedTranscriptService { SharedTranscriptService(replica: Replica(store: laterStore, identity: later)) }
    var notesService: SharedTranscriptService { SharedTranscriptService(replica: Replica(store: phoneStore, identity: notesOnly)) }
    var expiredService: SharedTranscriptService { SharedTranscriptService(replica: Replica(store: phoneStore, identity: expired)) }
    var otherAgentService: SharedTranscriptService {
      SharedTranscriptService(replica: Replica(store: phoneStore, identity: otherAgent))
    }

    func save() throws -> SharedTranscriptReference {
      let replica = Replica(store: phoneStore, identity: person)
      let document = TranscriptDocument(text: "The harbour is quiet. Keep this exact line.",
        words: [.init(text: "The harbour is quiet.", start: 10, end: 14)])
      _ = try replica.saveTranscript(document, episode: "episode", show: "show", source: "publisher", language: "en")
      let reference = try SharedTranscriptService(replica: replica).reference(episode: "episode")
      return try #require(reference)
    }

    func sync() async throws { _ = try await StoreSync(local: laterStore, remote: LocalRemote(phoneStore)).run() }

    /// A second enrolled member signs the same sealed operation under its own key. Replica
    /// admits both records because it verifies signatures but does not enforce unique IDs.
    func duplicateSignedOperation(_ id: String, by signer: SoftwareIdentity) throws {
      let path = try #require(phoneStore.snapshot.keys.first { $0.hasPrefix("ops/") && $0.hasSuffix("-\(id).json") })
      let bytes = try phoneStore.read(path)
      let original = try #require(bytes)
      let header = try Canonical.decode(OperationHeader.self,
        from: Canonical.decode(SignedRecord.self, from: original).body)
      let duplicate = OperationHeader(author: signer.id, namespace: header.namespace, epoch: header.epoch,
        sealed: header.sealed)
      let record = try SignedRecord(signing: Canonical.encode(duplicate), with: signer)
      try phoneStore.create(LibraryPath.operation(author: signer.id, clock: 999_999, id: id),
        Canonical.encode(record))
    }

    func revokeAgent(seen kept: [String]? = nil) throws {
      try AuthorityHolder(log: AuthorityLog(store: phoneStore), root: root).revoke(agent.id, seen: kept)
    }

    func signContext(kind: String, version: Int = 1, body: [String: JSONValue],
      commandID: String, as signer: SoftwareIdentity) throws
    {
      var payload = body
      payload["commandID"] = .string(commandID)
      payload["commandDigest"] = .string(Canonical.digest(try Canonical.encode(body)))
      _ = try Replica(store: phoneStore, identity: signer).perform(
        Command(namespace: Podcasts.namespace, kind: kind, v: version, payload: payload))
    }
  }

  @Test func immutableTranscriptAndAttributedAcceptanceRoundTrip() async throws {
    let f = try Fixture()
    let reference = try f.save()
    let quote = SharedTranscriptCitation(quote: "The harbour is quiet.")
    let proposed = try f.agentService.propose(reference: reference, citation: quote, text: "Notice the quiet harbour.",
      contributionID: "context-1", commandID: "agent-command-1")
    let proposalID = try #require(proposed.revision)
    #expect(proposed.outcome == .applied)
    let accepted = try f.taupe.accept(reference: reference, contributionID: "context-1",
      proposalRevision: proposalID, commandID: "person-command-1", expectedRevision: proposalID,
      note: "I want to remember the silence.")
    #expect(accepted.outcome == .applied)
    try await f.sync()
    let later = f.laterService
    #expect(try later.references().contains(reference))
    #expect(try later.reference(episode: "episode") == reference)
    #expect(try later.resolve(reference, citation: quote).text == "The harbour is quiet. Keep this exact line.")
    let contribution = try #require(later.state(for: reference).contributions.first)
    #expect(contribution.proposedBy == f.agent.id)
    #expect(contribution.acceptedBy == f.person.id)
    #expect(contribution.proposalRevision == proposalID)
    #expect(contribution.acceptanceRevision == accepted.revision)
    #expect(contribution.intentionalNote == "I want to remember the silence.")
    #expect(try later.state(for: reference).receipts.count == 2)
    #expect(try later.state(for: reference).currentRevisionByContributionID["context-1"] == accepted.revision)
    #expect(try later.state(for: reference).transcriptAuthor == f.person.id)
    #expect(try later.state(for: reference).transcriptAuthorLabel == "Taupe phone")
    #expect(throws: SharedTranscriptError.wrongCitation) {
      try later.resolve(reference, citation: .init(quote: "invented sentence"))
    }
  }

  @Test func callerReceiptsReplayAndChangedReuseReject() throws {
    let f = try Fixture()
    let reference = try f.save()
    let citation = SharedTranscriptCitation(quote: "The harbour is quiet.")
    let first = try f.agentService.propose(reference: reference, citation: citation, text: "Consider the harbour.",
      contributionID: "context", commandID: "stable")
    let replay = try f.agentService.propose(reference: reference, citation: citation, text: "Consider the harbour.",
      contributionID: "context", commandID: "stable")
    #expect(replay == first)
    #expect(try f.taupe.state(for: reference).contributions.count == 1)
    #expect(try f.taupe.state(for: reference).receipts.count == 1)
    #expect(throws: SharedTranscriptError.commandIDConflict) {
      try f.agentService.propose(reference: reference, citation: citation, text: "Different suggestion.",
        contributionID: "context", commandID: "stable")
    }
    let stale = try f.agentService.propose(reference: reference, citation: citation, text: "Offline edit.",
      contributionID: "context", commandID: "stale")
    #expect(stale.outcome == .staleRevision)
    #expect(stale.observedRevision == first.revision)
    let staleReplay = try f.agentService.propose(reference: reference, citation: citation, text: "Offline edit.",
      contributionID: "context", commandID: "stale")
    #expect(staleReplay == stale)
  }

  @Test func rolesAndCurrentNamespaceAreNotPayloadClaims() throws {
    let f = try Fixture()
    let reference = try f.save()
    let quote = SharedTranscriptCitation(quote: "The harbour is quiet.")
    #expect(throws: SharedTranscriptError.wrongRole) {
      try f.taupe.propose(reference: reference, citation: quote, text: "Fake agent proposal",
        contributionID: "fake", commandID: "fake-1")
    }
    #expect(throws: SharedTranscriptError.wrongRole) {
      try f.agentService.accept(reference: reference, contributionID: "fake", proposalRevision: "fake",
        commandID: "fake-2", expectedRevision: nil)
    }
    #expect(throws: SharedTranscriptError.noCurrentAccess) { try f.notesService.references() }
    #expect(throws: SharedTranscriptError.noCurrentAccess) { try f.expiredService.references() }
  }

  @Test func oldRevisionResolvesAfterASelectionChange() throws {
    let f = try Fixture()
    let original = try f.save()
    let replacement = TranscriptDocument(text: "A corrected line.", words: [.init(text: "A corrected line.", start: 11, end: 15)])
    try Replica(store: f.phoneStore, identity: f.person).saveTranscript(replacement, episode: "episode", show: "show",
      source: "publisher", language: "en")
    #expect(try f.taupe.reference(episode: "episode")?.revision != original.revision)
    #expect(try f.taupe.resolve(original, citation: .init(quote: "The harbour is quiet.")).text
      == "The harbour is quiet. Keep this exact line.")
  }

  @Test func duplicateSignedTranscriptRevisionFailsClosed() throws {
    let f = try Fixture()
    let reference = try f.save()
    try f.duplicateSignedOperation(reference.revision, by: f.agent)
    let matches = try f.taupe.replica.read(Podcasts.namespace).admitted
      .filter { $0.operation.id == reference.revision }
    #expect(matches.count == 2)
    #expect(throws: SharedTranscriptError.duplicateOperationID(reference.revision)) {
      try f.taupe.references()
    }
    #expect(throws: SharedTranscriptError.duplicateOperationID(reference.revision)) {
      try f.taupe.resolve(reference)
    }
  }

  @Test func currentRevisionIdentifiesSupersededProposal() throws {
    let f = try Fixture()
    let reference = try f.save()
    let quote = SharedTranscriptCitation(quote: "The harbour is quiet.")
    let first = try f.agentService.propose(reference: reference, citation: quote, text: "First thought.",
      contributionID: "context", commandID: "first")
    let firstRevision = try #require(first.revision)
    let second = try f.agentService.propose(reference: reference, citation: quote, text: "Revised thought.",
      contributionID: "context", commandID: "second", expectedRevision: firstRevision)
    let secondRevision = try #require(second.revision)
    let state = try f.taupe.state(for: reference)
    #expect(state.contributions.count == 2)
    #expect(state.currentRevisionByContributionID["context"] == secondRevision)
  }

  @Test func anotherAgentCannotTakeOverAnExistingContributionID() throws {
    let f = try Fixture()
    let reference = try f.save()
    let quote = SharedTranscriptCitation(quote: "The harbour is quiet.")
    let original = try f.agentService.propose(reference: reference, citation: quote, text: "Original.",
      contributionID: "shared-id", commandID: "agent-a")
    let originalRevision = try #require(original.revision)
    let takeover = try f.otherAgentService.propose(reference: reference, citation: quote, text: "Takeover.",
      contributionID: "shared-id", commandID: "agent-b", expectedRevision: originalRevision)
    #expect(takeover.outcome == .invalidProposal)
    #expect(takeover.observedRevision == originalRevision)
    let replay = try f.otherAgentService.propose(reference: reference, citation: quote, text: "Takeover.",
      contributionID: "shared-id", commandID: "agent-b", expectedRevision: originalRevision)
    #expect(replay == takeover)
    let state = try f.taupe.state(for: reference)
    #expect(state.contributions.count == 1)
    #expect(state.contributions.first?.proposedBy == f.agent.id)
    #expect(state.currentRevisionByContributionID["shared-id"] == originalRevision)
    let revision = try f.agentService.propose(reference: reference, citation: quote, text: "Owner revision.",
      contributionID: "shared-id", commandID: "agent-a-next", expectedRevision: originalRevision)
    #expect(revision.outcome == .applied)
  }

  @Test func malformedSignedContextClaimsDoNotApply() throws {
    let f = try Fixture()
    let reference = try f.save()
    let seed = try f.agentService.propose(reference: reference, citation: .init(quote: "The harbour is quiet."),
      text: "Seed thought.", contributionID: "seed", commandID: "seed")
    let seedID = try #require(seed.revision)
    let seedOperation = try #require(f.taupe.replica.read(Podcasts.namespace).admitted
      .first { $0.operation.id == seedID }?.operation)
    var malformedBody = seedOperation.payload
    malformedBody["commandID"] = nil
    malformedBody["commandDigest"] = nil
    malformedBody["contributionID"] = .string("bad-expect")
    malformedBody["expectedRevision"] = .number(7)
    try f.signContext(kind: SharedTranscriptService.proposeKind, body: malformedBody,
      commandID: "malformed-expect", as: f.agent)
    malformedBody["contributionID"] = .string("bad-version")
    malformedBody["expectedRevision"] = .null
    try f.signContext(kind: SharedTranscriptService.proposeKind, version: 2, body: malformedBody,
      commandID: "malformed-version", as: f.agent)
    let referenceJSON = try #require(seedOperation.payload["reference"])
    let acceptanceBody: [String: JSONValue] = [
      "reference": referenceJSON, "contributionID": .string("seed"),
      "expectedRevision": .string(seedID), "proposalRevision": .string(seedID), "note": .number(4)
    ]
    try f.signContext(kind: SharedTranscriptService.acceptKind, body: acceptanceBody,
      commandID: "malformed-note", as: f.person)
    let state = try f.taupe.state(for: reference)
    #expect(state.contributions.count == 1)
    #expect(state.contributions.first?.acceptanceRevision == nil)
    #expect(state.receipts.count == 1)
  }

  @Test func missingBlobPausesOnlyItsContributionChain() throws {
    let f = try Fixture()
    let readable = try f.save()
    let readableProposal = try f.agentService.propose(reference: readable,
      citation: .init(quote: "The harbour is quiet."), text: "Readable thought.",
      contributionID: "readable-context", commandID: "readable-proposal")
    let readableProposalID = try #require(readableProposal.revision)
    let phone = Replica(store: f.phoneStore, identity: f.person)
    _ = try phone.saveTranscript(TranscriptDocument(text: "A second exact source.", words: nil),
      episode: "second", show: "show", source: "publisher", language: "en")
    let possibleMissing = try f.taupe.reference(episode: "second")
    let missing = try #require(possibleMissing)
    let proposed = try f.agentService.propose(reference: missing, citation: .init(quote: "second exact"),
      text: "Second source thought.", contributionID: "second-context", commandID: "second-proposal")
    #expect(proposed.outcome == .applied)
    let missingProposalID = try #require(proposed.revision)
    let dependent = try f.taupe.accept(reference: missing, contributionID: "second-context",
      proposalRevision: missingProposalID, commandID: "second-accept", expectedRevision: missingProposalID,
      note: "Keep second thought.")
    #expect(dependent.outcome == .applied)
    let missingPath = LibraryPath.blob(missing.blob.digest)
    let snapshot = f.phoneStore.snapshot
    for (path, bytes) in snapshot where path != missingPath { try f.laterStore.create(path, bytes) }
    let later = f.laterService
    let beforeState = try later.state(for: readable)
    #expect(beforeState.contributions.count == 1)
    #expect(beforeState.receipts.count == 1)
    #expect(throws: SharedTranscriptError.missingTranscript) { try later.state(for: missing) }
    let before = try f.laterStore.list(LibraryPath.operations + "/" + f.later.id).count
    let accepted = try later.accept(reference: readable, contributionID: "readable-context",
      proposalRevision: readableProposalID, commandID: "readable-accept", expectedRevision: readableProposalID)
    #expect(accepted.outcome == .applied)
    let after = try f.laterStore.list(LibraryPath.operations + "/" + f.later.id).count
    #expect(after == before + 1)
    let blob = try #require(snapshot[missingPath])
    try f.laterStore.create(missingPath, blob)
    let resolved = try later.state(for: missing)
    #expect(resolved.contributions.count == 1)
    #expect(resolved.contributions.first?.intentionalNote == "Keep second thought.")
    #expect(resolved.receipts.count == 2)
    #expect(resolved.receipts.allSatisfy { $0.outcome == .applied })
  }

  @Test func duplicateSignedProposalRevisionFailsClosed() throws {
    let f = try Fixture()
    let reference = try f.save()
    let proposal = try f.agentService.propose(reference: reference, citation: .init(quote: "The harbour is quiet."),
      text: "Notice the harbour.", contributionID: "context", commandID: "proposal")
    let revision = try #require(proposal.revision)
    try f.duplicateSignedOperation(revision, by: f.otherAgent)
    let matches = try f.taupe.replica.read(Podcasts.namespace).admitted.filter { $0.operation.id == revision }
    #expect(matches.count == 2)
    #expect(throws: SharedTranscriptError.duplicateOperationID(revision)) {
      try f.taupe.state(for: reference)
    }
  }

  @Test func revokedAgentCannotReplayPriorReceipt() throws {
    let f = try Fixture()
    let reference = try f.save()
    let quote = SharedTranscriptCitation(quote: "The harbour is quiet.")
    _ = try f.agentService.propose(reference: reference, citation: quote, text: "Notice the harbour.",
      contributionID: "context", commandID: "stable")
    try f.revokeAgent()
    #expect(throws: SharedTranscriptError.noCurrentAccess) {
      try f.agentService.propose(reference: reference, citation: quote, text: "Notice the harbour.",
        contributionID: "context", commandID: "stable")
    }
  }

  @Test func acceptedNoteRemainsVisibleWhenHolderKeepsObservedProposal() throws {
    let f = try Fixture()
    let reference = try f.save()
    let proposed = try f.agentService.propose(reference: reference, citation: .init(quote: "The harbour is quiet."),
      text: "Notice the harbour.", contributionID: "context", commandID: "proposal")
    let proposalID = try #require(proposed.revision)
    let accepted = try f.taupe.accept(reference: reference, contributionID: "context",
      proposalRevision: proposalID, commandID: "accept", expectedRevision: proposalID, note: "Keep this.")
    #expect(accepted.outcome == .applied)
    try f.revokeAgent()
    let state = try f.taupe.state(for: reference)
    #expect(state.contributions.first?.acceptedBy == f.person.id)
    #expect(state.contributions.first?.intentionalNote == "Keep this.")
    #expect(state.heldContextCount == 0)
  }

  @Test func excludedProposalIsHeldAndAcceptanceDoesNotProject() throws {
    let f = try Fixture()
    let reference = try f.save()
    let proposed = try f.agentService.propose(reference: reference, citation: .init(quote: "The harbour is quiet."),
      text: "Notice the harbour.", contributionID: "context", commandID: "proposal")
    let proposalID = try #require(proposed.revision)
    _ = try f.taupe.accept(reference: reference, contributionID: "context",
      proposalRevision: proposalID, commandID: "accept", expectedRevision: proposalID, note: "Keep this.")
    try f.revokeAgent(seen: [])
    let state = try f.taupe.state(for: reference)
    #expect(state.heldContextCount == 1)
    #expect(state.contributions.isEmpty)
    #expect(state.receipts.first?.outcome == .staleRevision)
  }
}
