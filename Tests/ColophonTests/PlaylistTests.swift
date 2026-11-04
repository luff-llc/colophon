import ColophonAuthority
import ColophonCore
import ColophonListening
import ColophonMCP
import ColophonReplica
import ColophonStore
import Foundation
import Testing

@Suite struct PlaylistTests {
  private func library() throws -> Replica {
    let store = MemoryStore()
    let member = SoftwareIdentity()
    _ = try AuthorityHolder.create(in: store, label: "Playlist test", root: SoftwareIdentity(),
      firstMember: member.publicIdentity, memberLabel: "Player", custody: .software,
      namespaces: [Podcasts.namespace])
    return Replica(store: store, identity: member)
  }

  @Test func savedPlaylistIsReadBackWithItsRule() throws {
    let replica = try library()
    let playlist = Listening.Playlist(id: "commute", name: "  Commute  ", shows: ["a", "b", "a"], order: .byShow)
    let operation = try replica.perform(Podcasts.savePlaylist(playlist, expect: nil))
    let state = try replica.state(of: Podcasts.self)
    let saved = try #require(state.playlists["commute"])
    #expect(saved.name == "Commute")
    let shows: [String] = ["a", "b"]
    #expect(saved.shows == shows)
    #expect(saved.order == .byShow)
    #expect(saved.revision == operation.id)
  }

  @Test func staleSaveIsKeptBesideTheCurrentVersion() throws {
    let replica = try library()
    let first = try replica.perform(Podcasts.savePlaylist(Listening.Playlist(id: "p", name: "Morning"), expect: nil))
    _ = try replica.perform(Podcasts.savePlaylist(Listening.Playlist(id: "p", name: "Mornings"), expect: first.id))
    // Written by someone who had only seen the first version.
    _ = try replica.perform(Podcasts.savePlaylist(Listening.Playlist(id: "p", name: "Breakfast"), expect: first.id))
    let state = try replica.state(of: Podcasts.self)
    let playlist = try #require(state.playlists["p"])
    #expect(playlist.name == "Mornings")
    #expect(playlist.competing.count == 1)
    #expect(playlist.competing.first?.name == "Breakfast")
  }

  @Test func archivedPlaylistLeavesTheActiveList() throws {
    let replica = try library()
    var playlist = Listening.Playlist(id: "p", name: "Old", mode: .manual, episodes: ["e1", "e2"])
    let saved = try replica.perform(Podcasts.savePlaylist(playlist, expect: nil))
    playlist.archived = true
    _ = try replica.perform(Podcasts.savePlaylist(playlist, expect: saved.id))
    let state = try replica.state(of: Podcasts.self)
    #expect(state.activePlaylists.isEmpty)
    #expect(state.playlists["p"]?.archived == true)
  }

  @Test func agentsCanSaveAndListPlaylistsThroughTheGeneratedTools() throws {
    let adapter = ModuleAdapter(Podcasts.self)
    let saveTool = adapter.operations.contains { $0.kind == Podcasts.PlaylistKind.save }
    let listTool = adapter.queries.contains { $0.name == "playlists" }
    #expect(saveTool)
    #expect(listTool)
    let replica = try library()
    _ = try replica.perform(Podcasts.savePlaylist(Listening.Playlist(id: "p", name: "Agent's pick"), expect: nil))
    let query = try #require(adapter.queries.first { $0.name == "playlists" })
    let result = try query.run(replica, [:])
    let names = result.object?["playlists"]?.array?.compactMap { $0.object?["name"]?.string } ?? []
    let expected: [String] = ["Agent's pick"]
    #expect(names == expected)
  }

  @Test func playlistWithoutANameIsIgnored() throws {
    let replica = try library()
    _ = try? replica.perform(Podcasts.savePlaylist(Listening.Playlist(id: "p", name: " "), expect: nil))
    let state = try replica.state(of: Podcasts.self)
    #expect(state.playlists.isEmpty)
  }

  @Test func smartRulesAreReadBack() throws {
    let replica = try library()
    var playlist = Listening.Playlist(id: "short", name: "Short and new", allShows: true)
    playlist.pinned = ["fav", "fav", "second"]
    playlist.included = ["keep-me"]
    playlist.progress = .unplayed
    playlist.maxMinutes = 30
    playlist.titleContains = "  interview  "
    try replica.perform(Podcasts.savePlaylist(playlist, expect: nil))
    let saved = try #require(try replica.state(of: Podcasts.self).playlists["short"])
    let pinned: [String] = ["fav", "second"]
    #expect(saved.pinned == pinned)
    let included: [String] = ["keep-me"]
    #expect(saved.included == included)
    #expect(saved.progress == .unplayed)
    #expect(saved.maxMinutes == 30)
    #expect(saved.titleContains == "interview")
  }

  @Test func aPlaylistSavedWithoutRulesKeepsTodaysBehaviour() throws {
    let replica = try library()
    try replica.perform(Podcasts.command(Podcasts.PlaylistKind.save, ["playlist": .string("old"),
      "name": .string("Old"), "mode": .string("automatic"), "allShows": .bool(true)]))
    let saved = try #require(try replica.state(of: Podcasts.self).playlists["old"])
    #expect(saved.pinned.isEmpty)
    #expect(saved.progress == .any)
    #expect(saved.maxMinutes == nil)
    #expect(saved.titleContains == nil)
  }
}
