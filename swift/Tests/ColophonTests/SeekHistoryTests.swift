import ColophonListening
import Foundation
import Testing

@Suite struct SeekHistoryTests {
  private func key(library: String = "library-a", episode: String = "episode-a", audio: String = "audio-a")
    -> SeekHistory.Key
  {
    SeekHistory.Key(library: library, episode: episode, audio: audio)
  }

  private func entry(origin: Double = 10, destination: Double = 20, revision: String? = nil)
    -> SeekHistory.Entry
  {
    SeekHistory.Entry(origin: origin, destination: destination, reason: .scrub, positionRevision: revision)
  }

  @Test func entriesAndEpisodesStayWithinTheirBounds() {
    var history = SeekHistory()
    let crowded = key(library: "bounds-library", episode: "crowded")
    for index in 0..<(SeekHistory.maxEntriesPerEpisode + 3) {
      let destination = Double(index + 20)
      let accepted = history.append(entry(destination: destination), for: crowded)
      #expect(accepted)
    }
    #expect(history.count(for: crowded) == SeekHistory.maxEntriesPerEpisode)
    #expect(history.latest(for: crowded)?.destination == Double(SeekHistory.maxEntriesPerEpisode + 22))

    var oldest: SeekHistory.Key?
    var newest: SeekHistory.Key?
    for index in 0...SeekHistory.maxEpisodes {
      let episodeKey = key(library: "episode-limit", episode: "episode-\(index)")
      if index == 0 { oldest = episodeKey }
      if index == SeekHistory.maxEpisodes { newest = episodeKey }
      let accepted = history.append(entry(destination: Double(index + 20)), for: episodeKey)
      #expect(accepted)
    }
    let firstKey = oldest
    let lastKey = newest
    #expect(firstKey != nil)
    #expect(lastKey != nil)
    if let firstKey { #expect(history.count(for: firstKey) == 0) }
    if let lastKey { #expect(history.count(for: lastKey) == 1) }
  }

  @Test func libraryEpisodeAndAudioEachIsolateTheirOwnBucket() {
    var history = SeekHistory()
    let base = key()
    let otherLibrary = key(library: "library-b")
    let otherEpisode = key(episode: "episode-b")
    let otherAudio = key(audio: "audio-b")
    for bucket in [base, otherLibrary, otherEpisode, otherAudio] {
      let accepted = history.append(entry(), for: bucket)
      #expect(accepted)
    }

    #expect(history.count(for: base) == 1)
    #expect(history.count(for: otherLibrary) == 1)
    #expect(history.count(for: otherEpisode) == 1)
    #expect(history.count(for: otherAudio) == 1)
    history.clear(for: otherAudio)
    #expect(history.count(for: otherAudio) == 0)
    #expect(history.count(for: base) == 1)
  }

  @Test func popRemovesOneEntryWithoutCreatingAnUndoEntry() {
    var history = SeekHistory()
    let bucket = key()
    let first = entry(origin: 5, destination: 15, revision: "revision-1")
    let second = entry(origin: 15, destination: 30, revision: "revision-2")
    let firstAccepted = history.append(first, for: bucket)
    let secondAccepted = history.append(second, for: bucket)
    #expect(firstAccepted)
    #expect(secondAccepted)

    let poppedSecond = history.pop(for: bucket)
    #expect(poppedSecond?.id == second.id)
    #expect(history.count(for: bucket) == 1)
    #expect(history.latest(for: bucket)?.id == first.id)
    let poppedFirst = history.pop(for: bucket)
    #expect(poppedFirst?.id == first.id)
    #expect(history.count(for: bucket) == 0)
    let emptyPop = history.pop(for: bucket)
    #expect(emptyPop == nil)
    #expect(history.count(for: bucket) == 0)
  }

  @Test func invalidEntriesAndIncompleteKeysAreRejected() {
    var history = SeekHistory()
    let bucket = key()
    let invalidEntries = [
      entry(origin: .nan, destination: 10),
      entry(origin: 0, destination: .infinity),
      entry(origin: -1, destination: 10),
      entry(origin: 10, destination: -1),
      entry(origin: 10, destination: 10.25),
    ]
    for value in invalidEntries {
      let accepted = history.append(value, for: bucket)
      #expect(!accepted)
    }

    let emptyLibrary = key(library: "")
    let emptyEpisode = key(episode: "")
    let emptyAudio = key(audio: "")
    let acceptedWithEmptyLibrary = history.append(entry(), for: emptyLibrary)
    let acceptedWithEmptyEpisode = history.append(entry(), for: emptyEpisode)
    let acceptedWithEmptyAudio = history.append(entry(), for: emptyAudio)
    #expect(!acceptedWithEmptyLibrary)
    #expect(!acceptedWithEmptyEpisode)
    #expect(!acceptedWithEmptyAudio)
    #expect(history.count(for: bucket) == 0)
  }

  @Test func persistedHistoryRestoresEntriesAndTheirPositionRevision() throws {
    let folder = FileManager.default.temporaryDirectory.appending(path: "seek-history-test-\(UUID().uuidString)",
      directoryHint: .isDirectory)
    let file = folder.appending(path: "seek-history.json")
    defer { try? FileManager.default.removeItem(at: folder) }

    var history = SeekHistory()
    let bucket = key(library: "persisted-library", episode: "persisted-episode", audio: "persisted-audio")
    let original = entry(origin: 42, destination: 147, revision: "position-revision-4")
    let accepted = history.append(original, for: bucket)
    #expect(accepted)
    try history.save(to: file)

    let restored = SeekHistory(contentsOf: file)
    #expect(restored.count(for: bucket) == 1)
    let restoredEntry = restored.latest(for: bucket)
    #expect(restoredEntry?.id == original.id)
    #expect(restoredEntry?.origin == original.origin)
    #expect(restoredEntry?.destination == original.destination)
    #expect(restoredEntry?.reason == original.reason)
    #expect(restoredEntry?.positionRevision == original.positionRevision)
  }

  @Test func revisionMarkerCanAdvanceAndClearIsScopedToItsKey() {
    var history = SeekHistory()
    let bucket = key(library: "revision-library", episode: "revision-episode", audio: "revision-audio")
    let related = key(library: "revision-library", episode: "other-episode", audio: "revision-audio")
    let original = entry(revision: "position-revision-before")
    let originalAccepted = history.append(original, for: bucket)
    let relatedAccepted = history.append(entry(revision: "other-position"), for: related)
    #expect(originalAccepted)
    #expect(relatedAccepted)

    history.setRevision("position-revision-after", for: original.id, key: bucket)
    let updated = history.latest(for: bucket)
    #expect(updated?.positionRevision == "position-revision-after")
    history.clear(for: bucket)
    #expect(history.count(for: bucket) == 0)
    #expect(history.count(for: related) == 1)
  }

  @Test func verifiedHistorySurvivesAbsentProvisionalMoveAndPromotionDropsUnverifiableChain() throws {
    let folder = FileManager.default.temporaryDirectory.appending(path: "seek-move-test-\(UUID().uuidString)",
      directoryHint: .isDirectory)
    let file = folder.appending(path: "seek-history.json")
    defer { try? FileManager.default.removeItem(at: folder) }

    let verified = key(library: "move-library", episode: "move-episode", audio: "verified-digest")
    let provisional = key(library: "move-library", episode: "move-episode", audio: "file-fingerprint")
    let saved = entry(origin: 100, destination: 140, revision: "verified-position")
    let olderVerified = entry(origin: 140, destination: 160, revision: "verified-position-next")
    var history = SeekHistory()
    let savedAccepted = history.append(saved, for: verified)
    let olderAccepted = history.append(olderVerified, for: verified)
    #expect(savedAccepted)
    #expect(olderAccepted)
    try history.save(to: file)

    var restored = SeekHistory(contentsOf: file)
    restored.move(from: provisional, to: verified)
    #expect(restored.count(for: verified) == 2)
    #expect(restored.latest(for: verified)?.id == olderVerified.id)
    #expect(restored.latest(for: verified)?.positionRevision == "verified-position-next")

    var provisionalEntries: [SeekHistory.Entry] = []
    for index in 0..<(SeekHistory.maxEntriesPerEpisode + 3) {
      let value = entry(origin: Double(400 + index * 10), destination: Double(405 + index * 10),
        revision: "provisional-\(index)")
      let accepted = restored.append(value, for: provisional)
      #expect(accepted)
      provisionalEntries.append(value)
    }

    restored.move(from: provisional, to: verified)
    #expect(restored.count(for: provisional) == 0)
    #expect(restored.count(for: verified) == SeekHistory.maxEntriesPerEpisode)
    let expected = Array(provisionalEntries.suffix(SeekHistory.maxEntriesPerEpisode))
    var popped: [SeekHistory.Entry] = []
    for _ in 0..<SeekHistory.maxEntriesPerEpisode {
      if let value = restored.pop(for: verified) { popped.append(value) }
    }
    let actualIDs = Array(popped.reversed().map(\.id))
    let expectedIDs = expected.map(\.id)
    #expect(actualIDs == expectedIDs)
    #expect(restored.count(for: verified) == 0)
  }
}
