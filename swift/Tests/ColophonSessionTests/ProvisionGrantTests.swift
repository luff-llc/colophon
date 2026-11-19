import Foundation
import Testing
import ColophonKit
import ColophonSavedKit
@testable import ColophonSession

/// Provisioning a home slot by a grant (the reference home's gate "grant", relay/README.md "Provisioning by a grant"),
/// through the Swift session against the REAL relay: an operator account on the relay's own slot, a test rig that asks
/// for `services` and is approved with an expiry and a slot prefix, and the rig's `provisionRequest` plugged into a fresh
/// account's `HomeConfiguration.request`. The relay's clock is set to the device's before each request; nothing waits on
/// elapsed time beyond the home's own head tick, which `settle` polls for.
@MainActor @Suite(.serialized) struct ProvisionGrantTests {
    nonisolated private static let prefix = "https://door.test/v1/libraries/"
    nonisolated private static let audience = "https://door.test/v1/provision"
    nonisolated private static let purpose = "home.provision"
    /// "The slot starts with `ci-`, or the call names no slot": conditions bind every call of the member (§12.3 step 7),
    /// its reads of the operator account's history at the home included, whose args name no slot (§10.4: a missing
    /// path makes `prefix` false).
    private static let slotPrefix = #"[{"any":[{"prefix":["args.slot","ci-"]},{"not":{"prefix":["args.slot",""]}}]}]"#

    private func settle(_ device: Device, tries: Int = 40) async -> Bool {
        for _ in 0..<tries {
            let ok = await device.session.syncNow()
            if ok, device.session.homeIssues.isEmpty, device.session.homeFaults.isEmpty { return true }
            try? await Task.sleep(for: .milliseconds(150))
        }
        return false
    }
    /// A device that asked learns its approval through the home (a pass before the home's next head may still see
    /// `refused:revoked` from its own check).
    private func untilApproved(_ device: Device, tries: Int = 20) async -> Bool {
        for _ in 0..<tries {
            _ = await device.session.syncNow()
            await device.session.refresh()
            if device.session.phase == .ready { return true }
            try? await Task.sleep(for: .milliseconds(100))
        }
        return false
    }
    private func describe(_ device: Device) -> String {
        "phase \(device.session.phase) error \(device.session.lastError ?? "-") issues \(device.session.homeIssues) faults \(device.session.homeFaults.map { "\($0.fault.kind) \($0.fault.status.map(String.init) ?? "")" })"
    }
    private func authorityOnly(_ medium: MemoryMedium) -> MemoryMedium { MemoryMedium(files: medium.snapshot().filter { $0.key.hasPrefix("authority/") }) }
    private func refusedOutOfScope(_ body: () async throws -> Void) async -> Bool {
        do { try await body(); return false } catch let error as ColophonError { return error.code == "refused:outOfScope" } catch { return false }
    }
    nonisolated private static func provision(_ account: String) -> String {
        #"{"enabled":true,"prefix":"\#(prefix)","gate":["grant"],"operator":{"account":"\#(account)","slot":"home"},"audience":"\#(audience)"}"#
    }
    private static func date(_ d: Date) -> String {
        let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime]; return f.string(from: d)
    }

    @Test func servicesInRequestTermsAndAGrantThatNarrowsThem() throws {
        let services = [ServiceTerms(audience: Self.audience, purposes: [Self.purpose, "home.read"])]
        let asked = SessionWorker.terms(namespaces: [], access: [.read], expires: nil, budget: nil, services: services)
        #expect(asked == #"{"services":[{"audience":"https://door.test/v1/provision","purposes":["home.provision","home.read"]}]}"#)
        #expect(SessionWorker.terms(namespaces: ["notes"], access: [.read, .write], expires: nil, budget: nil) == #"{"records":[{"access":"write","namespace":"notes"}]}"#)
        let granted = try SessionWorker.narrowed(requestTerms: asked, grant: ServiceGrant(services: [ServiceTerms(audience: Self.audience, purposes: [Self.purpose])],
            expires: "2026-12-01T00:00:00Z", conditionsJSON: #"[{"prefix":["args.slot","ci-"]}]"#))
        #expect(granted == #"{"conditions":[{"prefix":["args.slot","ci-"]}],"expires":"2026-12-01T00:00:00Z","services":[{"audience":"https://door.test/v1/provision","purposes":["home.provision"]}]}"#)
        for wider in [ServiceGrant(services: [ServiceTerms(audience: "https://other.test/x", purposes: [Self.purpose])]),
                      ServiceGrant(services: [ServiceTerms(audience: Self.audience, purposes: ["home.release"])]),
                      ServiceGrant(services: [ServiceTerms(audience: Self.audience, purposes: ["*"])]),
                      ServiceGrant(services: [])] {
            #expect(throws: SessionError.invalidCommand) { try SessionWorker.narrowed(requestTerms: asked, grant: wider) }
        }
        #expect(throws: SessionError.invalidCommand) {
            try SessionWorker.narrowed(requestTerms: #"{"expires":"2026-11-01T00:00:00Z","services":[{"audience":"urn:x","purposes":["a"]}]}"#, grant: ServiceGrant(expires: "2026-12-01T00:00:00Z"))
        }
    }

    @Test func aRigGrantedByTheOperatorProvisionsAFreshAccount() async throws {
        let relay = RelayHome(base: "https://door.test/v1/accounts/operator-swift", port: RelayHome.freePort())
        defer { relay.stop() }
        // The operator account lives on the relay's own slot `home`, which the door names as its operator slot.
        let operatorHome = HomeConfiguration(endpoint: URL(string: relay.base + "/")!, request: { account in
            try relay.start(account: account, provision: Self.provision(account))
            return try relay.memberRequest(account: account)
        }, transport: relay.transport())
        let op = Device(homes: [operatorHome], createWithoutHome: false)
        await op.session.create()
        op.session.stopSync()
        try #require(op.session.phase == .ready, "\(describe(op))")
        #expect(await settle(op), "\(describe(op))")

        // The rig joins the operator account asking only for the door's service.
        let rig = Device(medium: authorityOnly(op.medium), homes: [HomeConfiguration(endpoint: URL(string: relay.base + "/")!, transport: relay.transport())],
                         createWithoutHome: false, namespaces: [], services: [ServiceTerms(audience: Self.audience, purposes: [Self.purpose])])
        await rig.session.restore()
        rig.session.stopSync()
        guard case .waitingForApproval = rig.session.phase else { Issue.record("expected waiting, got \(describe(rig))"); return }
        let scanned = try await op.session.scanRequest(try await rig.session.exportRequest())
        #expect(scanned.request.services == [ServiceTerms(audience: Self.audience, purposes: [Self.purpose])])
        #expect(scanned.request.namespaces.isEmpty)
        await #expect(throws: SessionError.invalidCommand) {
            try await op.session.approve(scanned.request, pairing: scanned.pairing,
                                         services: ServiceGrant(services: [ServiceTerms(audience: "https://other.test/v1/provision", purposes: [Self.purpose])]))
        }
        let again = try await op.session.scanRequest(try await rig.session.exportRequest())
        try await op.session.approve(again.request, pairing: again.pairing,
                                     services: ServiceGrant(expires: Self.date(Date().addingTimeInterval(86_400)), conditionsJSON: Self.slotPrefix))
        let rigID = try #require(rig.session.memberID)
        #expect(op.session.members.first { $0.id == rigID }?.expiresMs != nil, "the grant carries its expiry")
        #expect(await settle(op), "\(describe(op))")
        #expect(await untilApproved(rig), "the rig learns its approval: \(describe(rig))")

        // The signer's own check: a purpose or an audience the rig was not granted is refused here; nothing is sent.
        let args = #"{"account":"\#(String(repeating: "ab", count: 32))","base":"\#(Self.prefix)ci-swift-x","slot":"ci-swift-x"}"#
        #expect(await refusedOutOfScope { _ = try await rig.session.signCall(audience: Self.audience, purpose: "home.release", argsJSON: args) })
        #expect(await refusedOutOfScope { _ = try await rig.session.signCall(audience: "https://other.test/v1/provision", purpose: Self.purpose, argsJSON: args) })

        // A fresh account whose home request is the rig's provisionRequest: provisioned, written, read on a second device.
        let slot = "ci-swift-\(UUID().uuidString.prefix(8).lowercased())", base = Self.prefix + slot
        let rigSession = rig.session
        let appHome = HomeConfiguration(endpoint: URL(string: base + "/")!, request: { account in
            try await rigSession.provisionRequest(door: relay.door, audience: Self.audience, slot: slot, base: base, account: account, transport: relay.doorTransport())
        }, transport: relay.slotTransport(base: base, slot: slot))
        let app = Device(homes: [appHome], createWithoutHome: false)
        await app.session.create()
        app.session.stopSync()
        try #require(app.session.phase == .ready, "\(describe(app))")
        #expect(app.session.homes.count == 1, "the provisioned home is appointed")
        try await app.session.perform(try .saveLink(id: "a", url: URL(string: "https://example.org/a")!, title: "A"), observed: app.session.observedRevision)
        #expect(await settle(app), "\(describe(app))")
        let second = Device(medium: authorityOnly(app.medium), homes: [HomeConfiguration(endpoint: URL(string: base + "/")!, transport: relay.slotTransport(base: base, slot: slot))],
                            createWithoutHome: false)
        await second.session.restore()
        second.session.stopSync()
        try await approveByScan(joining: second.session, approving: app.session)
        #expect(await settle(app), "\(describe(app))")
        #expect(await untilApproved(second), "\(describe(second))")
        #expect(await settle(second), "\(describe(second))")
        #expect(try await SavedStore(session: second.session).load(ItemsQuery(limit: 50)).get().total == 1, "the second device reads what the first wrote")

        // A slot outside the grant's prefix: the rig's own check refuses it (the condition is false); nothing is sent.
        #expect(await refusedOutOfScope {
            _ = try await rig.session.provisionRequest(door: relay.door, audience: Self.audience, slot: "other-swift", base: Self.prefix + "other-swift",
                                                       account: String(repeating: "cd", count: 32), transport: relay.doorTransport())
        })
        // The door's own refusal is final: a call for one slot carried with another slot's body is 403, nothing made.
        let call = try await rig.session.signCall(audience: Self.audience, purpose: Self.purpose,
            argsJSON: #"{"account":"\#(String(repeating: "cd", count: 32))","base":"\#(Self.prefix)ci-swift-y","slot":"ci-swift-y"}"#)
        let body = Data(#"{"account":"\#(String(repeating: "cd", count: 32))","base":"\#(Self.prefix)other-swift","slot":"other-swift"}"#.utf8)
        let refused = try await relay.doorTransport().send(HttpRequest(ticket: 0, home: "", method: .post, url: relay.door.absoluteString, headers: [
            Header(name: "Content-Type", value: "application/json"), Header(name: "Content-Length", value: String(body.count)),
            Header(name: "Authorization", value: "Colophon \(call)")], body: body))
        #expect(refused.status == 403)
        #expect(HomeRefusal(status: refused.status, headers: refused.headers, body: refused.body)?.code == "refused:outOfScope")

        // The operator revokes the rig: the rig, which has not synced the revocation, signs; the door refuses it.
        try await op.session.revoke(memberID: rigID)
        #expect(await settle(op), "\(describe(op))")
        do {
            _ = try await rig.session.provisionRequest(door: relay.door, audience: Self.audience, slot: "ci-swift-z", base: Self.prefix + "ci-swift-z",
                                                       account: String(repeating: "ef", count: 32), transport: relay.doorTransport())
            Issue.record("a revoked rig provisioned")
        } catch let refusal as ProvisionRefusal {
            #expect(refusal.status == 403 && refusal.code == "refused:revoked", "\(refusal)")
        }
    }
}
