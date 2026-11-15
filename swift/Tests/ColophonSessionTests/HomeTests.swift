import CryptoKit
import Foundation
import Testing
import ColophonSavedKit
import ColophonSession

@MainActor struct HomeTests {
    private func configured(_ home: SimHome, owner: SoftwareKeys = SoftwareKeys(), medium: MemoryMedium = MemoryMedium(), appoint: Bool) -> Device {
        let make: @Sendable (String) async throws -> Data = { account in
            home.setAccount(account)
            return try home.memberRequest(account: account, createdMs: Int64(Date().timeIntervalSince1970 * 1000) - 5000)
        }
        let transport = HomeConfiguration(endpoint: URL(string: home.base + "/")!, label: "Home", request: appoint ? make : nil, transport: home)
        return Device(medium: medium, owner: owner, homes: [transport], createWithoutHome: false)
    }

    /// Device one creates an account with the in-process home appointed (spec §18), writes, and syncs. Device two
    /// has its own folder (a copy of the authority objects, as iCloud would deliver them), asks for access
    /// through its request, is approved, and reads what device one wrote through the home.
    @Test func twoSessionsSyncThroughAnInProcessHome() async throws {
        let home = SimHome()
        let first = configured(home, appoint: true)
        await first.session.create()
        first.session.stopSync()
        #expect(first.session.phase == .ready, "\(first.session.phase) \(first.session.lastError ?? "")")
        #expect(first.session.homes.count == 1, "the home is appointed at creation")
        #expect(!first.session.notices.noHome, "an account with a home does not warn")
        try await first.session.perform(try .saveLink(id: "a", url: URL(string: "https://example.org/a")!, title: "A"), observed: first.session.observedRevision)
        #expect(await first.session.syncNow())
        #expect(home.holds(prefix: "ops/").count == 1, "the home holds the member's record")
        #expect(home.entryCount >= 4)

        let second = configured(home, medium: MemoryMedium(files: first.medium.snapshot().filter { $0.key.hasPrefix("authority/") }), appoint: false)
        await second.session.restore()
        second.session.stopSync()
        guard case .waitingForApproval = second.session.phase else { Issue.record("expected waiting, got \(second.session.phase)"); return }
        try await first.session.importRequest(try await second.session.exportRequest())
        try await first.session.approve(try #require(first.session.requests.first))
        #expect(await first.session.syncNow())
        #expect(await second.session.syncNow())
        await second.session.refresh()
        #expect(second.session.phase == .ready, "\(second.session.phase) \(second.session.lastError ?? "")")
        #expect(await second.session.syncNow())
        #expect(try await SavedStore(session: second.session).load(ItemsQuery(limit: 10)).get().total == 1, "the second device reads what the first wrote")
        try await second.session.perform(try .saveLink(id: "b", url: URL(string: "https://example.org/b")!, title: "B"), observed: second.session.observedRevision)
        #expect(await second.session.syncNow())
        #expect(await first.session.syncNow())
        #expect(try await SavedStore(session: first.session).load(ItemsQuery(limit: 10)).get().total == 2)
        #expect(second.session.homeFaults.isEmpty && first.session.homeFaults.isEmpty, "an honest home raises no fault")
    }

    @Test func aHomeThatIsOfflineIsOfflineNotAnError() async throws {
        let home = SimHome()
        let device = configured(home, appoint: true)
        await device.session.create()
        device.session.stopSync()
        home.online = false
        #expect(await device.session.syncNow() == false)
        guard case .offline = device.session.syncState else { Issue.record("expected offline, got \(device.session.syncState)"); return }
        #expect(device.session.phase == .ready, "local reading and writing keep working")
        try await device.session.perform(try .saveLink(url: URL(string: "https://example.org/offline")!, title: "Offline"), observed: device.session.observedRevision)
        home.online = true
        #expect(await device.session.syncNow())
        #expect(home.holds(prefix: "ops/").count == 1)
    }
}
