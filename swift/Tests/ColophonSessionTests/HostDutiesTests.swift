import Foundation
import Testing
@testable import ColophonSession

/// The host duties of spec §17.5 the session computes and performs, against a simulated home.
@MainActor struct HostDutiesTests {
    private func homeConfiguration(_ home: SimHome, routes: [DeliveryRoute] = [], register: (@Sendable (String, [DeliveryRoute]) async throws -> Bool)? = nil) -> HomeConfiguration {
        let make: @Sendable (String) async throws -> Data = { account in
            home.setAccount(account)
            return try home.memberRequest(account: account, createdMs: Int64(Date().timeIntervalSince1970 * 1000) - 5_000)
        }
        return HomeConfiguration(endpoint: URL(string: home.base + "/")!, request: make, transport: home, deliveryRoutes: routes, registerRoutes: register)
    }

    @Test func anAccountWithOneDeviceIsWarnedAndOneWithASecondKeyIsNot() async throws {
        let alone = Device()
        await alone.session.create()
        #expect(alone.session.duties.soleDevice, "one control key: a stolen sole device can't be vetoed")
        let laptop = SoftwareKeys()
        let two = Device(additional: [AdditionalController(provider: laptop, label: "Laptop", roles: [.approve, .control])])
        await two.session.create()
        #expect(!two.session.duties.soleDevice)
    }

    /// Two routes on different devices are registered with each home that offers it; a home that does not, and a host
    /// with fewer than two routes, are states the UI shows.
    @Test func deliveryRoutesAreRegisteredOrTheirAbsenceIsShown() async throws {
        let routes = [DeliveryRoute(kind: .push, address: "token-a", reaches: "iPhone"), DeliveryRoute(kind: .email, address: "a@example.org", reaches: "mail")]
        let calls = RouteLog()
        let offered = SimHome()
        let device = Device(homes: [homeConfiguration(offered, routes: routes, register: { account, given in calls.add(account, given); return true })], createWithoutHome: false)
        await device.session.create()
        device.session.stopSync()
        #expect(calls.count == 1 && calls.routes == routes, "registered once with both routes")
        #expect(device.session.duties.routes.map(\.registered) == [true])

        let silent = SimHome()
        let other = Device(homes: [homeConfiguration(silent, routes: routes)], createWithoutHome: false)
        await other.session.create()
        other.session.stopSync()
        let state = try #require(other.session.duties.routes.first)
        #expect(!state.registered && state.detail.contains("does not offer notices"), "\(state.detail)")

        let one = Device(homes: [homeConfiguration(SimHome(), routes: [routes[0]])], createWithoutHome: false)
        await one.session.create()
        one.session.stopSync()
        #expect(one.session.duties.routes.first?.detail.contains("fewer than two") == true)
    }

    /// A transition is submitted to every home and retried until receipted; the outcome is a value. Polling follows
    /// recoveryDelay / 6, faster while a change is pending.
    @Test func aTransitionIsSubmittedUntilEveryHomeReceiptedItAndPollingFollowsTheDelay() async throws {
        let home = SimHome()
        let laptop = SoftwareKeys()
        let device = Device(homes: [homeConfiguration(home)], createWithoutHome: false,
                            additional: [AdditionalController(provider: laptop, label: "Laptop", roles: [.approve, .control])])
        await device.session.create()
        device.session.stopSync()
        #expect(device.session.duties.pollInterval == .seconds(259_200 / 6), "the default 72 h delay polls every 12 h")
        let account = try #require(device.session.libraryID)
        let second = SimHome(base: "https://second.example")
        let raw = try second.memberRequest(account: account, createdMs: Int64(Date().timeIntervalSince1970 * 1000) - 5_000)
        let change = "{\"homes\":{\"appoint\":[{\"request\":\"" + raw.base64EncodedString() + "\",\"terms\":{\"serves\":[\"home\"]}}]}}"
        let digest = try await device.session.proposeTransition(change)
        let submission = try #require(device.session.duties.submissions.first { $0.object == digest })
        #expect(submission.finished && submission.complete && submission.kind == .transition, "\(submission)")
        #expect(device.session.notices.pending.contains { $0.digest == digest })
        #expect(device.session.duties.pollInterval == .seconds(15), "faster while a change is pending")
    }

    /// At headQuorum 2 with one home receipting, a transition older than 300 s is dead and is offered to be signed again.
    @Test func aTransitionTooFewHomesReceiptedIsDeadAndCanBeSignedAgain() async throws {
        let home = SimHome()
        let clock = Clock()
        let device = Device(homes: [homeConfiguration(home)], createWithoutHome: false,
                            additional: [AdditionalController(provider: SoftwareKeys(), label: "Laptop", roles: [.approve, .control])],
                            clock: { clock.now })
        await device.session.create()
        device.session.stopSync()
        let account = try #require(device.session.libraryID)
        let second = SimHome(base: "https://second.example")
        let raw = try second.memberRequest(account: account, createdMs: Int64(Date().timeIntervalSince1970 * 1000) - 5_000)
        let change = "{\"homes\":{\"appoint\":[{\"request\":\"" + raw.base64EncodedString() + "\",\"terms\":{\"serves\":[\"home\"]}}]}}"
        // The home never receipts (offline): nothing reaches a quorum.
        home.online = false
        let digest = try await device.session.worker.submitTransition(change).0
        clock.advance(by: 301)
        await device.session.refresh()
        let dead = try #require(device.session.duties.deadTransitions.first { $0.digest == digest }, "\(device.session.duties)")
        #expect(dead.receipted == 0 && dead.quorum >= 1 && dead.canResign)
    }
}

final class RouteLog: @unchecked Sendable {
    private let lock = NSLock()
    private var entries: [(String, [DeliveryRoute])] = []
    func add(_ account: String, _ routes: [DeliveryRoute]) { lock.withLock { entries.append((account, routes)) } }
    var count: Int { lock.withLock { entries.count } }
    var routes: [DeliveryRoute] { lock.withLock { entries.last?.1 ?? [] } }
}

final class Clock: @unchecked Sendable {
    private let lock = NSLock()
    private var offset: TimeInterval = 0
    var now: Date { lock.withLock { Date().addingTimeInterval(offset) } }
    func advance(by seconds: TimeInterval) { lock.withLock { offset += seconds } }
}
