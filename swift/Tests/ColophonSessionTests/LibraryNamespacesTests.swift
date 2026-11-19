import Foundation
import Testing
import ColophonKeys
import ColophonSession

/// A session whose `libraryNamespaces` (what the account declares at genesis) is wider than its own `namespaces` (what
/// its member is granted) is ready after `create()`: readiness and published revisions follow the member's own
/// namespaces, not the library's. Before 0.5.0's final commit it came out `denied`.
@MainActor struct LibraryNamespacesTests {
    static let all = ["listening.podcasts", "notes", "reading.books", "reading.saved"]

    private func created(_ namespaces: [String], library: [String], home: SimHome? = nil) async -> Device {
        var homes: [HomeConfiguration] = []
        if let home {
            let make: @Sendable (String) async throws -> Data = { account in
                home.setAccount(account)
                return try home.memberRequest(account: account, createdMs: Int64(Date().timeIntervalSince1970 * 1000) - 5000)
            }
            homes = [HomeConfiguration(endpoint: URL(string: home.base + "/")!, label: "Home", request: make, transport: home)]
        }
        let device = Device(homes: homes, createWithoutHome: home == nil, namespaces: namespaces, libraryNamespaces: library)
        await device.session.create()
        return device
    }

    @Test(arguments: [false, true])
    func oneOwnNamespaceOfAllFourIsReady(withHome: Bool) async throws {
        let device = await created(["listening.podcasts"], library: Self.all, home: withHome ? SimHome() : nil)
        #expect(device.session.phase == .ready, "\(device.session.phase)")
        #expect(device.session.members.contains { $0.grant?.namespaces == ["listening.podcasts"] })
    }

    @Test(arguments: [false, true])
    func aNarrowerMemberThanTheLibraryIsReady(withHome: Bool) async throws {
        let device = await created(["reading.saved"], library: ["reading.saved", "notes"], home: withHome ? SimHome() : nil)
        #expect(device.session.phase == .ready, "\(device.session.phase)")
    }

    @Test(arguments: [false, true])
    func equalListsAreReady(withHome: Bool) async throws {
        let device = await created(["reading.saved", "notes"], library: ["reading.saved", "notes"], home: withHome ? SimHome() : nil)
        #expect(device.session.phase == .ready, "\(device.session.phase)")
    }
}
