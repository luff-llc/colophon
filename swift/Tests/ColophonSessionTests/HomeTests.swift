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
        #expect(first.session.homeIssues.isEmpty && second.session.homeIssues.isEmpty)
    }

    /// A home that demands calls for records and the change feed (§13.4): every such read goes with a call whose `args`
    /// are exactly `{"method","path","body"}` for that request, audience the home's base, and the home (checking as the
    /// relay does, signature and membership included) refuses none.
    @Test func readsAtAHomeThatDemandsCallsCarryCallsBoundToTheirRequest() async throws {
        let home = SimHome()
        home.requireCalls = true
        let device = configured(home, appoint: true)
        await device.session.create()
        device.session.stopSync()
        try await device.session.perform(try .saveLink(id: "a", url: URL(string: "https://example.org/a")!, title: "A"), observed: device.session.observedRevision)
        #expect(await device.session.syncNow(), "\(device.session.syncState) \(device.session.homeIssues)")
        #expect(await device.session.syncNow())
        #expect(home.acceptedCalls >= 2 && home.refusedCalls.isEmpty, "accepted \(home.acceptedCalls), refused \(home.refusedCalls)")
        #expect(home.holds(prefix: "ops/").count == 1)
        #expect(device.session.homeIssues.isEmpty)
    }

    /// Only `https` homes, unless the testing option allows loopback `http`; the session neither appoints nor contacts
    /// one that is not.
    @Test func onlyHTTPSHomesAreUsed() async throws {
        #expect(HomeLimits.isAllowed(URL(string: "https://home.example/v1/x")!, allowingLoopbackHTTP: false))
        #expect(!HomeLimits.isAllowed(URL(string: "http://home.example/")!, allowingLoopbackHTTP: false))
        #expect(!HomeLimits.isAllowed(URL(string: "http://home.example/")!, allowingLoopbackHTTP: true))
        #expect(!HomeLimits.isAllowed(URL(string: "http://127.0.0.1:8080/")!, allowingLoopbackHTTP: false))
        #expect(HomeLimits.isAllowed(URL(string: "http://127.0.0.1:8080/")!, allowingLoopbackHTTP: true))
        #expect(HomeLimits.isAllowed(URL(string: "http://localhost:8080/")!, allowingLoopbackHTTP: true))
        await #expect(throws: HomeTransportError.insecureEndpoint("http://home.example/head")) {
            _ = try await URLSessionHomeTransport().send(HttpRequest(ticket: 1, home: "h", method: .get, url: "http://home.example/head", headers: [], body: Data()))
        }
        let home = SimHome(base: "http://home.example")
        let make: @Sendable (String) async throws -> Data = { account in home.setAccount(account); return try home.memberRequest(account: account, createdMs: Int64(Date().timeIntervalSince1970 * 1000) - 5000) }
        let device = Device(homes: [HomeConfiguration(endpoint: URL(string: home.base + "/")!, request: make, transport: home)], createWithoutHome: false)
        await device.session.create()
        #expect(device.session.phase != .ready && device.session.lastError == SessionError.insecureHome.localizedDescription,
                "an http home is not appointed: \(device.session.phase) \(device.session.lastError ?? "")")
        #expect(home.requestLog.isEmpty, "nothing was sent to it")
    }

    /// A response over its bound is refused unread, by the URLSession transport (streamed) and for a host's transport.
    @Test func aResponseOverItsBoundIsRefused() async throws {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [LargeAnswer.self]
        let transport = URLSessionHomeTransport(configuration: configuration)
        await #expect(throws: HomeTransportError.responseTooLarge(limit: 64 * 1024)) {
            _ = try await transport.send(HttpRequest(ticket: 1, home: "h", method: .get, url: "https://home.example/head", headers: [], body: Data()))
        }
        let small = try await transport.send(HttpRequest(ticket: 2, home: "h", method: .get, url: "https://home.example/authority", headers: [], body: Data()))
        #expect(small.body.count == 200 * 1024, "a 200 KiB authority page is under its 32 MiB bound")
        #expect(HomeLimits.responseBytes(for: "https://h.example/records/blobs/" + String(repeating: "a", count: 64)) == 1024 * 1024)
        #expect(HomeLimits.responseBytes(for: "https://h.example/records/ops/a/n/1.json") == 41 * 1024 * 1024)
    }

    @Test func aHomeThatIsOfflineIsOfflineNotAnError() async throws {
        let home = SimHome()
        let device = configured(home, appoint: true)
        await device.session.create()
        device.session.stopSync()
        home.online = false
        #expect(await device.session.syncNow() == false)
        guard case .offline = device.session.syncState else { Issue.record("expected offline, got \(device.session.syncState)"); return }
        // The failed pass aborted and stored its report, which wakes a refresh: content stays usable meanwhile, and once
        // the refresh is done the session is ready (asserting `.ready` without the barrier raced that refresh).
        #expect(device.session.hasUsableContent, "local reading keeps working during the refresh: \(device.session.phase)")
        await device.session.flushExternalChanges()
        #expect(device.session.phase == .ready, "local reading and writing keep working: \(device.session.phase)")
        try await device.session.perform(try .saveLink(url: URL(string: "https://example.org/offline")!, title: "Offline"), observed: device.session.observedRevision)
        home.online = true
        #expect(await device.session.syncNow())
        #expect(home.holds(prefix: "ops/").count == 1)
    }
}

/// Answers every request with 200 KiB, without a Content-Length, so the bound is enforced while streaming.
final class LargeAnswer: URLProtocol, @unchecked Sendable {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        guard let url = request.url, let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [:]) else { return }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        for _ in 0..<50 { client?.urlProtocol(self, didLoad: Data(repeating: 7, count: 4096)) }
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}
