import Foundation
import Testing
@testable import ColophonSession

@MainActor struct MemberReadinessTests {
    @Test(arguments: [[], ["notes"]], [[], ["reading.saved"]])
    func expiryIsCheckedWithoutAnyGrantedLibraryNamespace(namespaces: [String], library: [String]) async throws {
        let clock = ReadinessClock()
        let first = Device(namespaces: ["notes"], libraryNamespaces: ["notes", "reading.saved"], clock: { clock.now })
        await first.session.create()
        try #require(first.session.phase == .ready)
        let services = [ServiceTerms(audience: "urn:test", purposes: ["read"])]
        let second = Device(medium: first.medium, namespaces: namespaces, services: services, libraryNamespaces: library, clock: { clock.now })
        await second.session.restore()
        let expiry = Date(timeIntervalSince1970: floor(clock.now.timeIntervalSince1970) + 3600)
        let scanned = try await first.session.scanRequest(try await second.session.exportRequest())
        try await first.session.approve(scanned.request, pairing: scanned.pairing,
                                        services: ServiceGrant(expires: ISO8601DateFormatter().string(from: expiry)))
        clock.advance(by: expiry.timeIntervalSince(clock.now))
        await second.session.refresh()
        #expect(second.session.phase == .ready, "\(second.session.phase)") // Inclusive expiry bound, like the core.
        clock.advance(by: 0.001)
        await second.session.refresh()
        #expect(second.session.phase == .denied, "\(second.session.phase)")
        #expect(second.session.namespaceRevisions.isEmpty)
    }

    @Test func provisionalAndRevokedMembersAreDeniedAndMissingEpochKeysStayUnavailable() async throws {
        let device = Device(namespaces: ["notes"])
        await device.session.create()
        let member = try #require(device.session.members.first { $0.id == device.session.memberID })
        let grant = try #require(member.grant)
        let emptyGrant = AccountGrant(namespaces: [], access: grant.access, expires: grant.expires, writeBudget: grant.writeBudget, import: grant.import)
        func changed(provisional: Bool, revokedAt: UInt64?) -> AccountMember {
            AccountMember(id: member.id, label: member.label, kind: member.kind, kindRaw: member.kindRaw, grant: emptyGrant,
                          since: member.since, revokedAt: revokedAt, writes: member.writes, expiresMs: member.expiresMs,
                          provisional: provisional, home: member.home, session: member.session, grantedBy: member.grantedBy)
        }
        for namespaces in [[], ["notes"]] {
            for denied in [changed(provisional: true, revokedAt: nil), changed(provisional: false, revokedAt: 1)] {
                var calls = 0
                let result = await memberReadiness(denied, nowMs: 0, namespaces: namespaces) { _ in calls += 1; return nil }
                #expect(result.phase == .denied)
                #expect(result.readable.isEmpty)
                #expect(calls == 0)
            }
        }
        for reason in [AccountDenialReason.unavailable, .notReadable] {
            var checked: [String] = []
            let result = await memberReadiness(member, nowMs: 0, namespaces: ["notes"]) { namespace in
                checked.append(namespace)
                return AccountDenial(reason: reason, reasonRaw: nil, detail: "epoch key not held")
            }
            #expect(checked == ["notes"])
            #expect(result.phase == .unavailable(reason: "epoch key not held"))
            #expect(result.readable.isEmpty)
        }
    }
    @Test func aRealMemberEngineWithoutUnlockedEpochKeysIsUnavailable() async throws {
        let device = Device(namespaces: ["notes"])
        await device.session.create()
        let account = try #require(device.session.libraryID)
        let key = try device.secrets.key(for: account)
        let engine = try await ColophonEngine.open(source: MediumSource(device.medium),
            listing: try device.medium.listing().map { ListedPath(path: $0.path, version: $0.version) },
            identity: AccountIdentity(kind: .member, id: try #require(device.session.memberID)),
            account: account, namespaces: ["notes"], deviceKey: key, nowMs: Int64(Date().timeIntervalSince1970 * 1000))
        do {
            let member = try #require(try await engine.run { try $0.me().member })
            let denial = try #require(try await engine.run { try $0.access(namespace: "notes") })
            #expect(denial.reason == .notReadable)
            let result = await memberReadiness(member, nowMs: Int64(Date().timeIntervalSince1970 * 1000), namespaces: ["notes"]) { _ in denial }
            if case .unavailable = result.phase {} else { Issue.record("expected unavailable, got \(result.phase)") }
            #expect(result.readable.isEmpty)
            await engine.lock()
        } catch {
            await engine.lock()
            throw error
        }
    }

}

/// A fixed clock keeps the inclusive expiry boundary independent of test execution time.
private final class ReadinessClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value = Date(timeIntervalSince1970: 1_800_000_000)
    var now: Date { lock.withLock { value } }
    func advance(by seconds: TimeInterval) { lock.withLock { value = value.addingTimeInterval(seconds) } }
}
