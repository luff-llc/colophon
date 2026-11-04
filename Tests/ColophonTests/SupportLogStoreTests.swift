import ColophonCore
import Foundation
import Testing

struct SupportLogStoreTests {
  @Test func errorsNeverExportPrivateDescriptions() async throws {
    let directory = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = SupportLogStore(directory: directory)
    let secret = "private-feed-url-secret-key"
    let error = NSError(domain: NSCocoaErrorDomain, code: 257,
      userInfo: [NSLocalizedDescriptionKey: secret, NSFilePathErrorKey: secret])
    await store.record(stage: .open, outcome: .failed, error: error)
    await store.record(stage: .publication, outcome: .failed, error: ColophonError.noAccess(secret))
    await store.record(stage: .refresh, outcome: .failed, error: NSError(domain: secret, code: 99))
    let report = await store.report()
    let json = String(decoding: try report.json(), as: UTF8.self)
    #expect(!json.contains(secret))
    #expect(report.events.count == 3)
    #expect(report.events.first?.failure?.category == .cocoa)
    #expect(report.events.first?.failure?.code == 257)
    #expect(report.events.last?.failure?.category == .unknown)
    #expect(report.events.last?.failure?.code == nil)
  }

  @Test func survivesRestartDeduplicatesAndClears() async throws {
    let directory = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let first = SupportLogStore(directory: directory)
    for _ in 0..<20 { await first.record(stage: .membership, outcome: .member) }
    await first.flush()
    let reopened = SupportLogStore(directory: directory)
    let report = await reopened.report()
    #expect(report.events.count == 1)
    #expect(report.logStorageAvailable)
    try await reopened.clear()
    let cleared = await SupportLogStore(directory: directory).report()
    #expect(cleared.events.isEmpty)
  }

  @Test func journalIsBoundedAndMalformedInputIsReported() async throws {
    let directory = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = SupportLogStore(directory: directory)
    for index in 0..<600 {
      await store.record(stage: .refresh, outcome: .failed,
        error: NSError(domain: NSCocoaErrorDomain, code: index))
    }
    let report = await store.report()
    #expect(report.events.count == SupportLogStore.maximumEvents)
    let path = directory.appending(path: "recent-events.json")
    let data = try Data(contentsOf: path)
    let exported = try report.json()
    #expect(data.count <= SupportLogStore.maximumBytes)
    #expect(exported.count <= SupportLogStore.maximumBytes)
    try Data(repeating: 65, count: SupportLogStore.maximumBytes + 1).write(to: path)
    let corrupted = await SupportLogStore(directory: directory).report()
    #expect(corrupted.events.isEmpty)
    #expect(!corrupted.logStorageAvailable)
  }

  @Test func contextHashesIdentityAndFixedFailuresRemainUseful() async throws {
    let directory = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = SupportLogStore(directory: directory)
    let library = "private-library-identity"
    await store.updateContext(libraryID: library, membership: .member, gauges: [.sourceFacts: 100, .sharedFacts: 80])
    await store.record(stage: .publication, outcome: .failed,
      failure: .init(category: .publicationRejected, code: 4))
    await store.record(stage: .open, outcome: .failed, error: NSError(domain: NSOSStatusErrorDomain, code: -25308))
    let report = await store.report()
    let json = String(decoding: try report.json(), as: UTF8.self)
    #expect(!json.contains(library))
    #expect(report.context?.libraryFingerprint == SupportContext(libraryID: library, membership: .member).libraryFingerprint)
    #expect(report.context?.gauges[.sharedFacts] == 80)
    #expect(report.events.first?.failure?.category == .publicationRejected)
    #expect(report.events.last?.failure?.category == .keychain)
    #expect(report.events.last?.failure?.code == -25308)
    let restored = await SupportLogStore(directory: directory).report()
    #expect(restored.context == report.context)
  }

  @Test func alternatingPollStagesAreDeduplicated() async {
    let directory = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = SupportLogStore(directory: directory)
    for _ in 0..<100 {
      await store.record(stage: .sourceExtraction, outcome: .started)
      await store.record(stage: .sourceExtraction, outcome: .succeeded)
      await store.record(stage: .publication, outcome: .started)
      await store.record(stage: .publication, outcome: .failed, failure: .init(category: .publicationRejected, code: 1))
    }
    let report = await store.report()
    #expect(report.events.count == 4)
  }


  @Test func recoveryAndFailureTransitionsAreNotDeduplicated() async {
    let directory = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = SupportLogStore(directory: directory)
    await store.record(stage: .publication, outcome: .failed, failure: .init(category: .publicationRejected, code: 1))
    await store.record(stage: .publication, outcome: .succeeded)
    await store.record(stage: .publication, outcome: .failed, failure: .init(category: .publicationRejected, code: 1))
    let report = await store.report()
    #expect(report.events.count == 3)
  }


  @Test func storedContextCannotInjectPrivateStringsOrUnboundedGauges() async throws {
    let directory = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = SupportLogStore(directory: directory)
    await store.updateContext(libraryID: "original", membership: .member, gauges: [.sourceFacts: 1])
    _ = await store.report()
    let path = directory.appending(path: "recent-events.json")
    let data = try Data(contentsOf: path)
    let parsed = try JSONSerialization.jsonObject(with: data) as? [String: Any]
    var object = try #require(parsed)
    var context = try #require(object["context"] as? [String: Any])
    let privateText = "https://private.example/secret-source"
    context["libraryFingerprint"] = privateText
    context["gauges"] = ["sourceFacts", -100, "pendingFacts", Int.max] as [Any]
    object["context"] = context
    try JSONSerialization.data(withJSONObject: object).write(to: path)
    let report = await SupportLogStore(directory: directory).report()
    let json = String(decoding: try report.json(), as: UTF8.self)
    #expect(!json.contains(privateText))
    #expect(report.context?.libraryFingerprint == nil)
    #expect(report.context?.gauges[.sourceFacts] == 0)
    #expect(report.context?.gauges[.pendingFacts] == 1_000_000_000)
  }

}
