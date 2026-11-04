import ColophonAuthority
import ColophonCore
import ColophonMCP
import ColophonNotes
import ColophonSaved
import ColophonReplica
import ColophonStore
import Foundation
import Testing

@Suite struct ScribendaFoundationTests {
  private struct Fixture {
    let store = MemoryStore()
    let person = SoftwareIdentity()
    let second = SoftwareIdentity()
    let agent = SoftwareIdentity()
    let denied = SoftwareIdentity()
    let holder: AuthorityHolder

    init() throws {
      holder = try AuthorityHolder.create(in: store, label: "Scribenda fixture", root: SoftwareIdentity(),
        firstMember: person.publicIdentity, memberLabel: "Person app", custody: .software,
        namespaces: [Notes.namespace, SavedLinks.namespace]).0
      try holder.admit(second.publicIdentity, label: "Second app", role: .app, custody: .software,
        namespaces: [Notes.namespace], write: true)
      try holder.admit(agent.publicIdentity, label: "Organiser", role: .agent, custody: .software,
        namespaces: [Notes.namespace], write: true)
      try holder.admit(denied.publicIdentity, label: "Other", role: .agent, custody: .software,
        namespaces: [SavedLinks.namespace], write: true)
      try app.perform(Notes.create(notebook: "n", title: "Universal notebook"))
      try app.perform(Notes.create(notebook: "foreign", title: "Another notebook"))
      try app.perform(Notes.putEntry("e", notebook: "n", title: "Lecture", date: "2026-10-19", tags: ["course"]))
    }
    var app: Replica { Replica(store: store, identity: person) }
    var otherApp: Replica { Replica(store: store, identity: second) }
    var organiser: Replica { Replica(store: store, identity: agent) }
    func state() throws -> Notebooks { try app.state(of: Notes.self) }
  }

  @Test func entryConflictsRetainMetadataAndAuthenticatedAuthors() throws {
    let f = try Fixture()
    let first = try #require(f.state().entries["e"])
    let changed = try f.app.perform(Notes.putEntry("e", notebook: "n", title: "My lecture", date: "2026-10-20",
      tags: ["revised"], expect: first.revision))
    let conflict = try f.otherApp.perform(Notes.putEntry("e", notebook: "n", title: "Other title", date: "2026-10-21",
      tags: ["alternate"], expect: first.revision))
    let entry = try #require(f.state().entries["e"])
    #expect(entry.title == "My lecture")
    #expect(entry.revision == changed.id)
    let alternative = try #require(entry.alternatives.first)
    #expect(alternative.title == "Other title")
    #expect(alternative.date == "2026-10-21")
    #expect(alternative.revision == conflict.id)
    #expect(alternative.author == f.second.id)
    #expect(alternative.authorLabel == "Second app")
    let fromSecond = try #require(f.otherApp.state(of: Notes.self).entries["e"])
    #expect(fromSecond == entry)
  }

  @Test func legacyCellsAndOutputsSurviveAndForeignNotebookCannotMutateThem() throws {
    let f = try Fixture()
    let original = try f.app.perform(Notes.putCell("c", notebook: "n", kind: .code, source: "1+1", language: "javascript", entry: "e"))
    try f.app.perform(Notes.output(cell: "c", notebook: "n", source: "1+1", runtime: "JavaScriptCore", outputs: [("text/plain", "2")]))
    let legacy = Notes.putCell("c", notebook: "n", kind: .code, source: "2+2", expect: original.id)
    #expect(legacy.payload["entry"] == nil)
    try f.otherApp.perform(legacy)
    let before = try #require(f.state().cells["c"])
    #expect(before.entry == "e")
    #expect(before.outputIsCurrent == false)
    let foreignEdit = try f.otherApp.perform(Notes.putCell("c", notebook: "foreign", kind: .raw, source: "Wrong", expect: before.revision))
    let foreignDelete = try f.otherApp.perform(Notes.deleteCell("c", notebook: "foreign"))
    let foreignEntry = try f.otherApp.perform(Notes.putCell("x", notebook: "foreign", kind: .markdown, source: "Wrong entry", entry: "e"))
    let state = try f.state()
    #expect(state.cells["c"] == before)
    #expect(state.cells["x"] == nil)
    #expect(state.invalidOperations.contains(foreignEdit.id))
    #expect(state.invalidOperations.contains(foreignDelete.id))
    #expect(state.invalidOperations.contains(foreignEntry.id))
  }

  @Test func attachmentsKeepExactBlobsAndStableIDsAreImmutable() throws {
    let f = try Fixture()
    let bytes = Data("original handout bytes".utf8)
    let blob = try f.app.putBlob(bytes, in: Notes.namespace)
    let command = Notes.attach("a", notebook: "n", role: .handout, name: "Handout.pdf", mime: "application/pdf", blob: blob)
    let first = try f.app.perform(command)
    try f.app.perform(command)
    let changed = try f.app.perform(Notes.attach("a", notebook: "n", role: .link, name: "Replacement", source: .init(url: "https://example.com")))
    let forgedOwner = try f.otherApp.perform(command)
    let state = try f.state()
    let a = try #require(state.attachments["a"])
    #expect(state.attachments.count == 1)
    #expect(a.revision == first.id)
    #expect(a.author == f.person.id)
    #expect(a.blob == blob)
    let retained = try f.otherApp.blob(blob, in: Notes.namespace)
    #expect(retained == bytes)
    #expect(state.invalidOperations.contains(changed.id))
    #expect(state.invalidOperations.contains(forgedOwner.id))
    #expect(state.attachments(in: "n", entry: nil).count == 1)
  }

  @Test func missingMaterialStaysVisibleAndMalformedTimedSourceDoesNotProject() throws {
    let f = try Fixture()
    let absent = BlobRef(digest: String(repeating: "a", count: 64), plain: String(repeating: "b", count: 64), epoch: 1, size: 12)
    try f.app.perform(Notes.attach("pending", notebook: "n", entry: "e", role: .file, name: "Waiting", blob: absent))
    let missing = try f.app.blob(absent, in: Notes.namespace)
    #expect(missing == nil)
    let invalidSource = NotesAttachment.SourceReference(libraryID: "library", namespace: "listening.podcasts",
      artifactID: "episode", revision: "revision", seconds: 21)
    let command = Notes.attach("invalid-time", notebook: "n", entry: "e", role: .audio, name: "Bad time", source: invalidSource)
    #expect(throws: ColophonError.self) { try Notes.validate(command.kind, command.payload) }
    let invalid = try f.app.perform(command)
    let state = try f.state()
    #expect(state.attachments(in: "n", entry: "e").count == 1)
    #expect(state.attachments["pending"]?.blob == absent)
    #expect(state.attachments["invalid-time"] == nil)
    #expect(state.invalidOperations.contains(invalid.id))
  }

  @Test func sourcePointersPinRevisionWithoutRequiringOrGrantingForeignAccess() throws {
    let f = try Fixture()
    let source = NotesAttachment.SourceReference(libraryID: "other-library", namespace: "listening.podcasts",
      artifactID: "episode", revision: "transcript-revision", quote: "A retained observation", page: nil,
      seconds: 21, recordingDigest: String(repeating: "a", count: 64))
    try f.app.perform(Notes.attach("source", notebook: "n", entry: "e", role: .reading, name: "Episode passage", source: source))
    let attachment = try #require(f.state().attachments["source"])
    #expect(attachment.source == source)
    #expect(attachment.source?.revision == "transcript-revision")
    let authority = try f.app.authority()
    let grant = try #require(authority.members[f.person.id]?.current)
    #expect(!grant.namespaces.contains("listening.podcasts"))
  }

  @Test func malformedDirectWritesNeverProjectAndMCPRejectsNestedShapes() throws {
    let f = try Fixture()
    let malformed = Notes.attach("bad", notebook: "n", role: .file, name: "No file")
    #expect(throws: ColophonError.self) { try Notes.validate(malformed.kind, malformed.payload) }
    let written = try f.app.perform(malformed)
    let badDate = try f.app.perform(Notes.putEntry("bad-date", notebook: "n", date: "2026-02-31"))
    let foreignEntry = try f.app.perform(Notes.putEntry("e", notebook: "foreign", title: "Hijacked"))
    let badBlob = BlobRef(digest: "not-a-digest", plain: "bad", epoch: -1, size: -2)
    let malformedBlob = try f.app.perform(Notes.attach("bad-blob", notebook: "n", role: .file, name: "Broken", blob: badBlob))
    let state = try f.state()
    #expect(state.attachments.isEmpty)
    #expect(state.entries["bad-date"] == nil)
    #expect(state.invalidOperations.contains(written.id))
    #expect(state.invalidOperations.contains(badDate.id))
    #expect(state.invalidOperations.contains(foreignEntry.id))
    #expect(state.invalidOperations.contains(malformedBlob.id))
    let server = MCPServer(replica: f.app, modules: [ModuleAdapter(Notes.self)])
    let response = try call(server, "notes__attachment_add", malformed.payload)
    #expect(response.object?["isError"]?.bool == true)
    let oldCommand = try SavedLinks.validated(SavedLinks.Kind.capture,
      ["item": "old", "url": "https://example.com", "title": "Old module"])
    #expect(oldCommand.namespace == SavedLinks.namespace)
  }

  @Test func proposalReviewAppendsAttributedContributionWithoutChangingCaptures() throws {
    let f = try Fixture()
    let original = try f.app.perform(Notes.putCell("raw", notebook: "n", kind: .markdown, source: "Unsorted original", entry: "e"))
    let inputs = ["raw": original.id]
    let command = Notes.propose("p", notebook: "n", entry: "e", title: "Suggested title", tags: ["research"],
      markdown: "## Organised\nAn interpretation", inputs: inputs)
    let proposed = try f.organiser.perform(command)
    try f.organiser.perform(command)
    let agentReview = try f.organiser.perform(Notes.reviewProposal("p", notebook: "n", keep: true))
    let review = try f.app.perform(Notes.reviewProposal("p", notebook: "n", keep: true, markdown: "My reviewed interpretation"))
    try f.app.perform(Notes.reviewProposal("p", notebook: "n", keep: true, markdown: "My reviewed interpretation"))
    let state = try f.state()
    let contribution = try #require(state.proposals["p"])
    #expect(state.proposals.count == 1)
    #expect(contribution.status == .kept)
    #expect(contribution.author == f.agent.id)
    #expect(contribution.revision == proposed.id)
    #expect(contribution.markdown == "## Organised\nAn interpretation")
    #expect(contribution.reviewedMarkdown == "My reviewed interpretation")
    #expect(contribution.reviewRevision == review.id)
    #expect(contribution.reviewedBy == f.person.id)
    #expect(state.cells["raw"]?.source == "Unsorted original")
    #expect(state.cells["raw"]?.revision == original.id)
    #expect(state.entries["e"]?.title == "Lecture")
    #expect(state.invalidOperations.contains(agentReview.id))
  }

  @Test func staleAndIncompleteProposalInputsCannotBeKept() throws {
    let f = try Fixture()
    let raw = try f.app.perform(Notes.putCell("raw", notebook: "n", kind: .raw, source: "First", entry: "e"))
    try f.organiser.perform(Notes.propose("p", notebook: "n", entry: "e", markdown: "Proposal", inputs: ["raw": raw.id]))
    let incomplete = try f.organiser.perform(Notes.propose("incomplete", notebook: "n", entry: "e", markdown: "Missing inputs", inputs: [:]))
    try f.app.perform(Notes.putCell("raw", notebook: "n", kind: .raw, source: "Second", expect: raw.id))
    let staleKeep = try f.app.perform(Notes.reviewProposal("p", notebook: "n", keep: true))
    let state = try f.state()
    #expect(state.proposals["p"]?.status == .pending)
    #expect(state.proposals["incomplete"] == nil)
    #expect(state.invalidOperations.contains(incomplete.id))
    #expect(state.invalidOperations.contains(staleKeep.id))
    try f.app.perform(Notes.reviewProposal("p", notebook: "n", keep: false))
    #expect(try f.state().proposals["p"]?.status == .dismissed)
  }

  @Test func addingCellOrConcurrentAlternativeInvalidatesPendingOrganisation() throws {
    let f = try Fixture()
    let raw = try f.app.perform(Notes.putCell("raw", notebook: "n", kind: .raw, source: "Capture", entry: "e"))
    try f.organiser.perform(Notes.propose("p", notebook: "n", entry: "e", markdown: "Interpretation", inputs: ["raw": raw.id]))
    try f.app.perform(Notes.putCell("new", notebook: "n", kind: .markdown, source: "Another thought", after: "raw", entry: "e"))
    let keep = try f.app.perform(Notes.reviewProposal("p", notebook: "n", keep: true))
    let state = try f.state()
    let pending = try #require(state.proposals["p"])
    #expect(!state.proposalInputsAreCurrent(pending))
    #expect(state.invalidOperations.contains(keep.id))
    #expect(pending.status == .pending)
    let newer = try f.app.perform(Notes.putCell("raw", notebook: "n", kind: .raw, source: "Edited", expect: raw.id))
    try f.otherApp.perform(Notes.putCell("raw", notebook: "n", kind: .raw, source: "Alternative", expect: raw.id))
    let current = try #require(f.state().cells["new"])
    let ambiguous = try f.organiser.perform(Notes.propose("ambiguous", notebook: "n", entry: "e", markdown: "Do not hide conflicts",
      inputs: ["raw": newer.id, "new": current.revision]))
    let conflicted = try f.state()
    #expect(conflicted.proposals["ambiguous"] == nil)
    #expect(conflicted.invalidOperations.contains(ambiguous.id))
  }

  @Test func generatedQueriesEnforceBoundsAndMemberGrants() throws {
    let f = try Fixture()
    let query = try #require(Notes.queries.first { $0.name == "entry" })
    let result = try query.run(f.organiser, ["notebook": "n", "entry": "e", "limit": .number(1)])
    #expect(result.object?["entry"]?.object?["entry"]?.string == "e")
    #expect(throws: ColophonError.self) { try query.run(f.organiser, ["notebook": "n", "entry": "e", "limit": .number(51)]) }
    let deniedReplica = Replica(store: f.store, identity: f.denied)
    #expect(throws: ColophonError.self) { try query.run(deniedReplica, ["notebook": "n", "entry": "e"]) }
    try f.holder.revoke(f.agent.id)
    let server = MCPServer(replica: f.organiser, modules: [ModuleAdapter(Notes.self)])
    let response = try call(server, "notes__entry_propose", Notes.propose("revoked", notebook: "n", entry: "e", markdown: "No", inputs: [:]).payload)
    #expect(response.object?["isError"]?.bool == true)
  }

  private func call(_ server: MCPServer, _ name: String, _ arguments: [String: JSONValue]) throws -> JSONValue {
    let request: JSONValue = .object(["jsonrpc": "2.0", "id": .number(1), "method": "tools/call",
      "params": .object(["name": .string(name), "arguments": .object(arguments)])])
    let data = try Canonical.encode(request)
    let response = try #require(server.handle(data))
    let decoded = try Canonical.decode(JSONValue.self, from: response)
    return try #require(decoded.object?["result"])
  }
}
