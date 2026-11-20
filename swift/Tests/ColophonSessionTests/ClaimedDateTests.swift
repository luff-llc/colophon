import Foundation
import Testing
import ColophonSession

/// `perform(_:observed:claimed:)`: an import keeps each note's original date as the operation's `created`.
@MainActor struct ClaimedDateTests {
    private static let listening = "listening.podcasts"

    private func addNote(_ id: String) throws -> DomainCommand {
        try DomainCommand(namespace: Self.listening, kind: "addNote",
                          payloadJSON: Data(#"{"id":"\#(id)","episode":"e1","show":"show","text":"An old thought"}"#.utf8))
    }
    private func created(_ session: ColophonSession, note id: String) async throws -> String? {
        let data = try await session.query(namespace: Self.listening, name: "note", arguments: Data(#"{"id":"\#(id)"}"#.utf8))
        // The query's outcome: `{"value":{"note":{...}}, ...}`.
        let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        let value = object?["value"] as? [String: Any]
        return (value?["note"] as? [String: Any])?["created"] as? String
    }

    @Test func aClaimedDateIsTheNotesCreatedAndAFutureOneIsRefused() async throws {
        let device = Device(namespaces: [Self.listening])
        await device.session.create()
        #expect(device.session.phase == .ready)
        // 2019-03-04T05:06:07.890Z, years before the account.
        let claimed = Date(timeIntervalSince1970: 1_551_675_967.890)
        let receipt = try await device.session.perform(try addNote("old"), observed: device.session.observedRevision, claimed: claimed)
        guard case .saved(let operation) = receipt, !operation.isEmpty else { Issue.record("not saved"); return }
        #expect(try await created(device.session, note: "old") == "2019-03-04T05:06:07.890Z")

        // Without a claim the date is now.
        let before = Date()
        try await device.session.perform(try addNote("new"), observed: device.session.observedRevision)
        let now = try #require(try await created(device.session, note: "new"))
        let plain = ISO8601DateFormatter(), fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let parsed = try #require(fractional.date(from: now) ?? plain.date(from: now))
        #expect(parsed.timeIntervalSince(before) > -2, "\(now)")

        // A claimed date later than now is refused and writes nothing.
        let files = device.medium.snapshot().count
        await #expect(throws: SessionError.invalidCommand) {
            try await device.session.perform(try addNote("future"), observed: device.session.observedRevision,
                                             claimed: Date().addingTimeInterval(3_600))
        }
        #expect(device.medium.snapshot().count == files)

        // A relaunch over the same medium reads the claimed date from the stored records.
        let again = device.relaunch()
        await again.restore()
        #expect(try await created(again, note: "old") == "2019-03-04T05:06:07.890Z")
    }
}
