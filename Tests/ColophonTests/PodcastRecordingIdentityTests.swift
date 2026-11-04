import ColophonAuthority
import ColophonCore
import ColophonListening
import ColophonReplica
import ColophonStore
import Foundation
import Testing

@Suite struct PodcastRecordingIdentityTests {
  private func library() throws -> Replica {
    let store = MemoryStore()
    let member = SoftwareIdentity()
    _ = try AuthorityHolder.create(in: store, label: "Recording test", root: SoftwareIdentity(),
      firstMember: member.publicIdentity, memberLabel: "Player", custody: .software,
      namespaces: [Podcasts.namespace])
    return Replica(store: store, identity: member)
  }

  @Test func changedBytesAtTheSameAddressCannotReuseCheckedTimings() async throws {
    let folder = FileManager.default.temporaryDirectory.appending(path: "recording-test-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: folder) }
    let file = folder.appending(path: "same-enclosure.mp3")
    try Data("first recording with a short ad".utf8).write(to: file)
    let first = try await PodcastRecordingIdentity.digest(of: file)
    let replica = try library()
    try replica.perform(Podcasts.segments(episode: "e", show: "s", audio: first,
      segments: [(10, 20, "sponsor")], source: "person"))
    try Data("second recording with a much longer inserted ad".utf8).write(to: file)
    let second = try await PodcastRecordingIdentity.digest(of: file)
    let state = try replica.state(of: Podcasts.self)
    #expect(first != second)
    let matched = state.segmentSet(for: "e", recordingDigest: first)
    #expect(matched?.segments.first?.start == 10)
    #expect(state.segmentSet(for: "e", recordingDigest: second) == nil)
    #expect(state.segmentSet(for: "e", recordingDigest: nil) == nil)
    #expect(state.segmentSet(for: "another-episode", recordingDigest: first) == nil)
  }

  @Test func urlReviewsRemainReadableWithoutBecomingVerified() throws {
    let replica = try library()
    let url = "https://example.test/episode.mp3"
    try replica.perform(Podcasts.segments(episode: "e", show: "s", audio: url,
      segments: [(10, 20, "sponsor")], source: "person"))
    let state = try replica.state(of: Podcasts.self)
    #expect(state.segments(for: "e", audio: url).count == 1)
    #expect(state.segmentSet(for: "e", recordingDigest: url) == nil)
    #expect(state.segmentSet(for: "e", recordingDigest: String(repeating: "a", count: 64)) == nil)
  }

  @Test func identicalBytesAcrossDevicesKeepTheSameReview() async throws {
    let folder = FileManager.default.temporaryDirectory.appending(path: "recording-test-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: folder) }
    let firstFile = folder.appending(path: "phone.mp3"), secondFile = folder.appending(path: "mac.mp3")
    // Spans several hashing chunks; the identity must be independent of local path.
    let bytes = Data(repeating: 42, count: 2_100_000)
    try bytes.write(to: firstFile)
    try bytes.write(to: secondFile)
    let first = try await PodcastRecordingIdentity.digest(of: firstFile)
    let second = try await PodcastRecordingIdentity.digest(of: secondFile)
    let phoneStore = MemoryStore(), macStore = MemoryStore()
    let phone = SoftwareIdentity(), mac = SoftwareIdentity()
    let (holder, _) = try AuthorityHolder.create(in: phoneStore, label: "Recording sync test", root: SoftwareIdentity(),
      firstMember: phone.publicIdentity, memberLabel: "Phone", custody: .software,
      namespaces: [Podcasts.namespace])
    try holder.admit(mac.publicIdentity, label: "Mac", role: .device, custody: .software,
      namespaces: [Podcasts.namespace], write: true)
    let phoneReplica = Replica(store: phoneStore, identity: phone)
    let macReplica = Replica(store: macStore, identity: mac)
    try phoneReplica.perform(Podcasts.segments(episode: "e", show: "s", audio: first,
      segments: [(10, 20, "sponsor")], source: "person"))
    let sync = StoreSync(local: macStore, remote: LocalRemote(phoneStore))
    try await sync.run()
    let received = try macReplica.state(of: Podcasts.self)
    #expect(first == second)
    #expect(received.segmentSet(for: "e", recordingDigest: second)?.source == "person")
    #expect(received.segmentSet(for: "e", recordingDigest: second)?.segments.first?.end == 20)

    // A checked edit on the second replica returns to the first with the same byte identity.
    try macReplica.perform(Podcasts.segments(episode: "e", show: "s", audio: second,
      segments: [(11, 19, "checked on Mac")], source: "person"))
    try await sync.run()
    let returned = try phoneReplica.state(of: Podcasts.self)
    #expect(returned.segmentSet(for: "e", recordingDigest: first)?.segments.first?.start == 11)
    #expect(returned.segmentSet(for: "e", recordingDigest: first)?.segments.first?.end == 19)
  }

  @Test func remoteAndMissingAudioCannotAcquireAnIdentity() async throws {
    let remote = try #require(URL(string: "https://example.test/episode.mp3"))
    await #expect(throws: (any Error).self) { try await PodcastRecordingIdentity.digest(of: remote) }
    let missing = FileManager.default.temporaryDirectory.appending(path: "missing-" + UUID().uuidString)
    await #expect(throws: (any Error).self) { try await PodcastRecordingIdentity.digest(of: missing) }
  }
}
