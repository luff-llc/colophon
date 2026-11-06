import ColophonAuthority
import ColophonCore
import ColophonListening
import ColophonMCP
@testable import ColophonReplica
import ColophonStore
import Foundation
import Testing

struct PodcastReadStateTests {
  private let feed = "https://example.invalid/podcast.xml"
  private let updated = Date(timeIntervalSince1970: 1_700_000_000)

  private func state(_ commands: [Command]) -> Listening {
    let operations = commands.enumerated().map { index, command in
      let operation = ColophonOperation(id: "operation-\(index)", kind: command.kind, v: command.v,
        clock: index, authority: 1, created: updated, payload: command.payload)
      return AdmittedOperation(operation: operation, author: "fixture", authorLabel: "Fixture",
        authorRole: .app, status: .admitted)
    }
    return Podcasts.fold(ReplicaView(operations: operations, rejected: [], unreadable: 0))
  }

  private func metadata() throws -> QueuedEpisodeMetadata {
    try QueuedEpisodeMetadata(episodeID: Podcasts.episodeID(feed: feed, guid: "known"),
      showID: Podcasts.showID(feed: feed), feedURL: feed, guid: "known", title: "Episode title",
      showTitle: "Saved show title", audioURL: "https://example.invalid/audio.mp3", duration: 600,
      published: 1_600_000_000)
  }

  @Test func queueDetailsPreserveOrderAndDistinguishMissingMetadata() throws {
    let saved = try metadata()
    let ids = ["unknown", saved.episodeID, "position-only"]
    let listening = state([
      Podcasts.follow(feed: feed, title: "Followed show"),
      Podcasts.position(episode: "position-only", show: saved.showID, seconds: 12, duration: 300,
        deliberate: false, expect: nil),
      try Podcasts.queue(ids, retaining: [saved]),
    ])
    let result = try #require(Podcasts.describe(listening).object)
    let legacyQueue = ids.map(JSONValue.string)
    #expect(result["queue"]?.array == legacyQueue)
    let details = try #require(result["queueDetails"]?.object)
    let episodes = try #require(details["episodes"]?.array)
    let detailIDs = episodes.compactMap { $0.object?["episode"]?.string }
    #expect(detailIDs == ids)
    #expect(details["total"]?.double == 3)
    #expect(details["hasMore"] == .bool(false))
    let unknown = try #require(episodes.first?.object)
    #expect(unknown["metadataAvailable"] == .bool(false))
    for field in ["title", "show", "showTitle", "duration", "published"] {
      #expect(unknown[field] == .null)
    }
    let known = try #require(episodes[1].object)
    #expect(known["metadataAvailable"] == .bool(true))
    #expect(known["title"]?.string == saved.title)
    #expect(known["showTitle"]?.string == saved.showTitle)
    #expect(known["duration"]?.double == 600)
    #expect(known["published"]?.double == saved.published)
    let positionOnly = try #require(episodes.last?.object)
    #expect(positionOnly["title"] == .null)
    #expect(positionOnly["showTitle"]?.string == "Followed show")
    #expect(positionOnly["duration"]?.double == 300)
    #expect(positionOnly["metadataAvailable"] == .bool(false))
  }

  @Test func latestKnownStateIsBoundedDeterministicAndPreservesLegacyInProgress() throws {
    let ids = (0..<55).map { "episode-\($0.formatted(.number.precision(.integerLength(2))))" }
    let commands = ids.enumerated().map { index, id in
      Podcasts.position(episode: id, show: "show", seconds: Double(index + 1), duration: 600,
        deliberate: false, expect: nil)
    }
    let listening = state(commands + [
      Podcasts.setState(episode: ids[54], show: "show", consumption: "completed", expect: nil),
      Podcasts.queue(ids),
    ])
    let result = try #require(Podcasts.describe(listening).object)
    let queue = try #require(result["queueDetails"]?.object)
    let queueIDs = queue["episodes"]?.array?.compactMap { $0.object?["episode"]?.string }
    let expectedQueueIDs = Array(ids.prefix(50))
    #expect(queueIDs == expectedQueueIDs)
    #expect(queue["total"]?.double == 55)
    #expect(queue["limit"]?.double == 50)
    #expect(queue["hasMore"] == .bool(true))
    let summary = try #require(result["listeningState"]?.object)
    let episodes = try #require(summary["episodes"]?.array)
    let summaryIDs = episodes.compactMap { $0.object?["episode"]?.string }
    let expectedSummaryIDs = Array(ids.reversed().prefix(20))
    #expect(summaryIDs == expectedSummaryIDs)
    #expect(summary["total"]?.double == 55)
    #expect(summary["limit"]?.double == 20)
    #expect(summary["hasMore"] == .bool(true))
    #expect(summary["semantics"]?.string == "latestKnownEpisodeStateNotSessionHistory")
    let completed = try #require(episodes.first?.object)
    #expect(completed["consumption"]?.string == "completed")
    #expect(completed["stateUpdatedAt"]?.double == updated.timeIntervalSince1970)
    #expect(completed["title"] == .null)
    #expect(completed["lastListened"] == nil)
    let expectedLegacy: [JSONValue] = ids.dropLast().reversed().prefix(20).enumerated().map { offset, id in
      .object(["episode": .string(id), "show": "show", "seconds": .number(Double(54 - offset)), "duration": .number(600)])
    }
    #expect(result["inProgress"]?.array == expectedLegacy)
    let repeated = Podcasts.describe(state(commands.reversed() + [
      Podcasts.setState(episode: ids[54], show: "show", consumption: "completed", expect: nil), Podcasts.queue(ids),
    ]))
    #expect(repeated == .object(result))
  }

  @Test func existingMCPReadToolReturnsReadableSavedMetadata() throws {
    let store = MemoryStore()
    let member = SoftwareIdentity()
    let holder = try AuthorityHolder.create(in: store, label: "Fixture", root: SoftwareIdentity(),
      firstMember: member.publicIdentity, memberLabel: "Fixture", role: .app, custody: .software,
      namespaces: [Podcasts.namespace]).0
    let replica = Replica(store: store, identity: member)
    let saved = try metadata()
    try replica.perform(Podcasts.queue([saved.episodeID], retaining: [saved]))
    let agent = SoftwareIdentity()
    try holder.admit(agent.publicIdentity, label: "Reader", role: .agent, custody: .software,
      namespaces: [Podcasts.namespace], write: false)
    let server = MCPServer(replica: Replica(store: store, identity: agent), modules: [ModuleAdapter(Podcasts.self)])
    let request = try Canonical.encode(["jsonrpc": "2.0", "id": .number(1), "method": "tools/call",
      "params": .object(["name": "listening_podcasts__read", "arguments": .object([:])])] as [String: JSONValue])
    let response = try #require(server.handle(request))
    let envelope = try JSONDecoder().decode(JSONValue.self, from: response)
    let content = try #require(envelope.object?["result"]?.object?["content"]?.array?.first?.object?["text"]?.string)
    let result = try JSONDecoder().decode(JSONValue.self, from: Data(content.utf8))
    let first = try #require(result.object?["queueDetails"]?.object?["episodes"]?.array?.first?.object)
    #expect(first["episode"]?.string == saved.episodeID)
    #expect(first["title"]?.string == saved.title)
    #expect(first["showTitle"]?.string == saved.showTitle)
  }
}
