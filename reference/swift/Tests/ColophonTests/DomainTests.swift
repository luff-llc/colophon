import ColophonAuthority
import ColophonBooks
import ColophonCore
import ColophonListening
import ColophonMCP
import ColophonNotes
import ColophonSaved
import ColophonReplica
import ColophonStore
import Foundation
import Testing

@Suite struct DomainTests {
  let store = MemoryStore()
  let phone = SoftwareIdentity()
  let mac = SoftwareIdentity()
  let holder: AuthorityHolder

  init() throws {
    let namespaces = [SavedLinks.namespace, Books.namespace, Podcasts.namespace, Notes.namespace]
    holder = try AuthorityHolder.create(in: store, label: "Library", root: SoftwareIdentity(), firstMember: phone.publicIdentity,
      memberLabel: "Phone", custody: .software, namespaces: namespaces).0
    try holder.admit(mac.publicIdentity, label: "Mac", role: .device, custody: .software, namespaces: namespaces, write: true)
  }

  var onPhone: Replica { Replica(store: store, identity: phone) }
  var onMac: Replica { Replica(store: store, identity: mac) }

  @Test func rereadingKeepsTheEarlierReading() throws {
    let added = try onPhone.perform(Books.add(book: "b1", title: "Middlemarch", author: "George Eliot"))
    let finished = try onPhone.perform(Books.setPlan(book: "b1", status: "finished", started: "2024-01-02",
      finished: "2024-03-01", expect: added.id))
    try onMac.perform(Books.setPlan(book: "b1", status: "reading", started: "2026-10-01", reread: true, expect: finished.id))
    let book = try #require(try onPhone.state(of: Books.self).books["b1"])
    #expect(book.readings.count == 2)
    #expect(book.readings.first?.status == "finished")
    #expect(book.status == "reading")
  }

  @Test func concurrentNoteEditsKeepBothVersions() throws {
    try onPhone.perform(Books.add(book: "b2", title: "Gilead", author: "Marilynne Robinson"))
    let note = try onPhone.perform(Books.note("n1", book: "b2", text: "First thought", quote: "I'm writing this because"))
    try onPhone.perform(Books.editNote("n1", text: "Phone's revision", expect: note.id))
    try onMac.perform(Books.editNote("n1", text: "Mac's revision", expect: note.id))
    let saved = try #require(try onMac.state(of: Books.self).notes["n1"])
    #expect(saved.text == "Phone's revision")
    #expect(saved.alternatives == ["Mac's revision"])
  }

  @Test func booksCanBeCorrectedRemovedAndNotesSettled() throws {
    try onPhone.perform(Books.add(book: "b3", title: "Middlemarc", author: "Eliot"))
    try onPhone.perform(Books.edit(book: "b3", title: "Middlemarch", pages: 880, extra: ["coverID": .number(42)]))
    let note = try onPhone.perform(Books.note("n3", book: "b3", text: "First"))
    try onPhone.perform(Books.editNote("n3", text: "Phone", expect: note.id))
    try onMac.perform(Books.editNote("n3", text: "Mac", expect: note.id))
    let current = try #require(try onMac.state(of: Books.self).notes["n3"])
    try onMac.perform(Books.resolveNote("n3", text: "Mac", expect: current.revision))
    let shelf = try onPhone.state(of: Books.self)
    let book = try #require(shelf.books["b3"])
    #expect(book.title == "Middlemarch")
    #expect(book.pages == 880)
    #expect(book.extra["coverID"] == .number(42))
    let settled = try #require(shelf.notes["n3"])
    #expect(settled.text == "Mac")
    #expect(settled.alternatives.isEmpty)
    try onPhone.perform(Books.remove(book: "b3"))
    let after = try onMac.state(of: Books.self)
    #expect(after.books["b3"] == nil)
    #expect(after.notes["n3"] == nil)
  }

  @Test func staleProgressNeverUndoesARewind() throws {
    let feed = "https://example.com/feed.xml"
    let episode = Podcasts.episodeID(feed: feed, guid: "ep-1")
    let show = Podcasts.showID(feed: feed)
    let start = try onPhone.perform(Podcasts.position(episode: episode, show: show, seconds: 600, duration: 3_600,
      deliberate: false, expect: nil))
    // The person rewinds on the Mac; the phone, still playing, reports passive progress from 600.
    try onMac.perform(Podcasts.position(episode: episode, show: show, seconds: 120, duration: 3_600, deliberate: true,
      expect: start.id))
    try onPhone.perform(Podcasts.position(episode: episode, show: show, seconds: 300, duration: 3_600, deliberate: false,
      expect: start.id))
    let seconds = try onPhone.state(of: Podcasts.self).episodes[episode]?.seconds
    #expect(seconds == 300) // forward from the rewind, and not back to 600
    // A stale passive report that would move backwards is ignored.
    try onPhone.perform(Podcasts.position(episode: episode, show: show, seconds: 200, duration: 3_600, deliberate: false,
      expect: start.id))
    let after = try onMac.state(of: Podcasts.self).episodes[episode]?.seconds
    #expect(after == 300)
  }

  @Test func notebookCellsOrderEditAndRecordOutput() throws {
    try onPhone.perform(Notes.create(notebook: "nb", title: "Linear algebra", kind: "lecture"))
    let first = try onPhone.perform(Notes.putCell("c1", notebook: "nb", kind: .markdown, source: "# Eigenvalues"))
    try onPhone.perform(Notes.putCell("c2", notebook: "nb", kind: .latex, source: #"A v = \lambda v"#, after: "c1"))
    let code = try onMac.perform(Notes.putCell("c3", notebook: "nb", kind: .code, source: "1 + 1", language: "javascript",
      after: "c2"))
    try onMac.perform(Notes.output(cell: "c3", notebook: "nb", source: "1 + 1", runtime: "JavaScriptCore",
      outputs: [("text/plain", "2")]))
    try onPhone.perform(Notes.putCell("c1", notebook: "nb", kind: .markdown, source: "# Eigenvalues and vectors",
      expect: first.id))
    try onMac.perform(Notes.putCell("c1", notebook: "nb", kind: .markdown, source: "# Eigen", expect: first.id))

    let state = try onPhone.state(of: Notes.self)
    let ids = state.cells(in: "nb").map(\.id)
    #expect(ids == ["c1", "c2", "c3"])
    let heading = try #require(state.cells["c1"])
    #expect(heading.source == "# Eigenvalues and vectors")
    #expect(heading.alternatives == ["# Eigen"])
    try onMac.perform(Notes.resolveCell("c1", notebook: "nb", source: "# Eigen", expect: heading.revision))
    let resolved = try #require(try onPhone.state(of: Notes.self).cells["c1"])
    #expect(resolved.source == "# Eigen")
    #expect(resolved.alternatives.isEmpty)
    let ran = try #require(state.cells["c3"])
    #expect(ran.outputIsCurrent)
    try onMac.perform(Notes.putCell("c3", notebook: "nb", kind: .code, source: "2 + 2", expect: code.id))
    #expect(try onPhone.state(of: Notes.self).cells["c3"]?.outputIsCurrent == false)
  }

  @Test func editsToDeletedCellsDontResurrectThem() throws {
    try onPhone.perform(Notes.create(notebook: "nb2", title: "Seminar"))
    let cell = try onPhone.perform(Notes.putCell("d1", notebook: "nb2", kind: .markdown, source: "Draft"))
    try onPhone.perform(Notes.deleteCell("d1", notebook: "nb2"))
    try onMac.perform(Notes.putCell("d1", notebook: "nb2", kind: .markdown, source: "Late edit", expect: cell.id))
    let state = try onPhone.state(of: Notes.self)
    #expect(state.cells["d1"] == nil)
    let late = state.editsToDeleted["d1"]
    #expect(late == ["Late edit"])
    let context = try #require(state.lateEdits["d1"]?.first)
    #expect(context.notebook == "nb2")
    #expect(context.kind == .markdown)
  }

  @Test func transcriptsNotesAndSegmentsAreSharedAndQueryable() throws {
    let feed = "https://example.com/show.xml"
    let episode = Podcasts.episodeID(feed: feed, guid: "e1")
    let show = Podcasts.showID(feed: feed)
    let words = [TranscriptDocument.Word(text: "Welcome", start: 0, end: 0.5), .init(text: "to", start: 0.5, end: 0.7),
      .init(text: "the", start: 0.7, end: 0.8), .init(text: "local-first", start: 0.8, end: 1.4),
      .init(text: "show", start: 1.4, end: 1.8)]
    try onMac.saveTranscript(TranscriptDocument(text: "Welcome to the local-first show", words: words), episode: episode,
      show: show, source: "onDevice", language: "en")
    try onMac.perform(Podcasts.segments(episode: episode, show: show, audio: "a1", segments: [(60, 120, "sponsor")],
      source: "person"))
    try onPhone.perform(Podcasts.segments(episode: episode, show: show, audio: "a1", segments: [(55, 130, "sponsor")],
      source: "detected", detector: "AppleSponsorAnalysis"))
    try onPhone.perform(Podcasts.note(episode: episode, show: show, seconds: 0.8, text: "Why local-first matters",
      quote: "local-first", origin: "ai"))

    // An untimed publisher transcript arriving later doesn't displace the timed one.
    try onPhone.saveTranscript(TranscriptDocument(text: "Publisher text without times", words: nil), episode: episode,
      show: show, source: "publisher", language: "en")
    let listening = try onPhone.state(of: Podcasts.self)
    let document = try #require(try onPhone.transcript(of: episode, in: listening))
    #expect(document.text == "Welcome to the local-first show")
    let kept = listening.segments(for: episode, audio: "a1").map(\.start)
    #expect(kept == [60]) // the person's review, not the later detection
    let origin = listening.notes(for: episode).first?.origin
    #expect(origin == "ai")

    let agent = SoftwareIdentity()
    try holder.admit(agent.publicIdentity, label: "Agent", role: .agent, custody: .software,
      namespaces: [Podcasts.namespace], write: true)
    let server = MCPServer(replica: Replica(store: store, identity: agent), modules: [ModuleAdapter(Podcasts.self)])
    let found = try call(server, "tools/call", ["name": "listening_podcasts__search_transcripts",
      "arguments": .object(["query": "local-first show"])])
    let text = found["result"]?.object?["content"]?.array?.first?.object?["text"]?.string ?? ""
    #expect(text.contains(episode))
    #expect(text.contains("0.8"))
  }

  @Test func mcpServerSpeaksForOneMember() throws {
    let agent = SoftwareIdentity()
    try holder.admit(agent.publicIdentity, label: "Claude", role: .agent, custody: .software,
      namespaces: [SavedLinks.namespace], write: true)
    let server = MCPServer(replica: Replica(store: store, identity: agent),
      modules: [ModuleAdapter(SavedLinks.self), ModuleAdapter(Notes.self)])

    let list = try call(server, "tools/list", [:])
    let names = list["result"]?.object?["tools"]?.array?.compactMap { $0.object?["name"]?.string } ?? []
    #expect(names.contains("reading_saved__capture_link"))
    #expect(names.contains("notes__cell_put"))

    let saved = try call(server, "tools/call", ["name": "reading_saved__capture_link", "arguments": .object([
      "item": "m1", "url": "https://example.com/m", "title": "From an agent"])])
    #expect(saved["result"]?.object?["isError"] == nil)
    let title = try onPhone.state(of: SavedLinks.self).items["m1"]?.title
    #expect(title == "From an agent")

    let missing = try call(server, "tools/call", ["name": "reading_saved__capture_link", "arguments": .object(["item": "m2"])])
    #expect(missing["result"]?.object?["isError"] == .bool(true))
    let forbidden = try call(server, "tools/call", ["name": "notes__notebook_create", "arguments": .object([
      "notebook": "x", "title": "Not allowed"])])
    #expect(forbidden["result"]?.object?["isError"] == .bool(true))
  }

  private func call(_ server: MCPServer, _ method: String, _ params: [String: JSONValue]) throws -> [String: JSONValue] {
    let request = try Canonical.encode(["jsonrpc": "2.0", "id": .number(1), "method": .string(method), "params": .object(params)]
      as [String: JSONValue])
    let response = try #require(server.handle(request))
    return try JSONDecoder().decode([String: JSONValue].self, from: response)
  }
}
