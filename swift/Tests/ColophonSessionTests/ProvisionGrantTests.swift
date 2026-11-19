import Foundation
import Testing
import ColophonKit
import ColophonSavedKit
@testable import ColophonSession

/// A clock a test moves by hand: every session and the relay read it, so nothing depends on real elapsed time.
final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var ms: Int64
    init(_ ms: Int64) { self.ms = ms }
    var now: Int64 { lock.withLock { ms } }
    var date: Date { Date(timeIntervalSince1970: Double(now) / 1000) }
    func advance(_ by: Int64) { lock.withLock { ms += by } }
    func set(_ to: Int64) { lock.withLock { ms = to } }
}

/// A member key that counts the signatures it is asked for.
final class CountingKeys: AsyncKeyProvider, @unchecked Sendable {
    private let inner: any AsyncKeyProvider = SoftwareKeys()
    private let lock = NSLock()
    private var count = 0
    var signs: Int { lock.withLock { count } }
    var form: KeyForm { inner.form }
    func assert(challenge: String, prfSalt: Data?) async throws -> KeyAssertion? { try await inner.assert(challenge: challenge, prfSalt: prfSalt) }
    func prf(salt: Data) async throws -> SecretBytes? { try await inner.prf(salt: salt) }
    func publicKeys() async throws -> PublicKeys { try await inner.publicKeys() }
    func sign(body: Data) async throws -> Data { lock.withLock { count += 1 }; return try await inner.sign(body: body) }
    func sharedSecret(peer: Data) async throws -> SecretBytes { try await inner.sharedSecret(peer: peer) }
    func keyDescriptor() async throws -> KeyDescriptorView { try await inner.keyDescriptor() }
}

/// Provisioning a home slot by a grant (the reference home's gate "grant", relay/README.md "Provisioning by a grant"),
/// through the Swift session against the REAL relay: an operator account on the relay's own slot, a test rig that asks
/// for `services` and is approved with an expiry and a slot condition, and the rig's `provisionRequest` plugged into a
/// fresh account's `HomeConfiguration.request`. Every session and the relay run on one fixed clock the test moves, and
/// the relay has no scheduler timer: heads are published by its test hook (`RelayHome.tick`), never by waiting.
@MainActor @Suite(.serialized) struct ProvisionGrantTests {
    nonisolated private static let prefix = "https://door.test/v1/libraries/"
    nonisolated private static let audience = "https://door.test/v1/provision"
    nonisolated private static let purpose = "home.provision"
    nonisolated private static let release = "home.release"
    nonisolated private static let t0: Int64 = 1_795_165_200_000 // 2026-11-20T09:00:00Z
    /// "The slot starts with `ci-`, or the call names no slot": conditions bind every call of the member (§12.3 step 7),
    /// its reads of the operator account's history at the home included, whose args name no slot (§10.4: a missing
    /// path makes `prefix` false).
    private static let slotPrefix = #"[{"any":[{"prefix":["args.slot","ci-"]},{"not":{"prefix":["args.slot",""]}}]}]"#

    /// Exchanges until clean, one relay pass after each exchange (the pass publishes the head covering what was uploaded).
    private func settle(_ device: Device, _ relay: RelayHome, _ clock: TestClock) async throws {
        for _ in 0..<6 {
            clock.advance(1000)
            let ok = await device.session.syncNow()
            try await relay.tick()
            if ok, device.session.homeIssues.isEmpty, device.session.homeFaults.isEmpty { return }
        }
        Issue.record("did not settle: \(describe(device))")
    }
    /// A device that asked learns its approval through the home, once the relay's pass covered it.
    private func untilApproved(_ device: Device, _ relay: RelayHome, _ clock: TestClock) async throws -> Bool {
        for _ in 0..<6 {
            clock.advance(1000)
            _ = await device.session.syncNow()
            await device.session.refresh()
            if device.session.phase == .ready { return true }
            try await relay.tick()
        }
        return false
    }
    private func describe(_ device: Device) -> String {
        "phase \(device.session.phase) error \(device.session.lastError ?? "-") issues \(device.session.homeIssues) faults \(device.session.homeFaults.map { "\($0.fault.kind) \($0.fault.status.map(String.init) ?? "")" })"
    }
    private func authorityOnly(_ medium: MemoryMedium) -> MemoryMedium { MemoryMedium(files: medium.snapshot().filter { $0.key.hasPrefix("authority/") }) }
    private func refused(_ code: String, _ body: () async throws -> Void) async -> Bool {
        do { try await body(); return false } catch let error as ColophonError { return error.code == code } catch { return false }
    }
    nonisolated private static func provision(_ account: String) -> String {
        #"{"enabled":true,"prefix":"\#(prefix)","gate":["grant"],"operator":{"account":"\#(account)","slot":"home"},"audience":"\#(audience)"}"#
    }
    private static func date(_ ms: Int64) -> String {
        let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime]; return f.string(from: Date(timeIntervalSince1970: Double(ms) / 1000))
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
                      ServiceGrant(services: [ServiceTerms(audience: Self.audience, purposes: [Self.release])]),
                      ServiceGrant(services: [ServiceTerms(audience: Self.audience, purposes: ["*"])]),
                      ServiceGrant(services: [])] {
            #expect(throws: SessionError.invalidCommand) { try SessionWorker.narrowed(requestTerms: asked, grant: wider) }
        }
        #expect(throws: SessionError.invalidCommand) {
            try SessionWorker.narrowed(requestTerms: #"{"expires":"2026-11-01T00:00:00Z","services":[{"audience":"urn:x","purposes":["a"]}]}"#, grant: ServiceGrant(expires: "2026-12-01T00:00:00Z"))
        }
    }

    /// The public combined overload, for a request with finite bounds (an expiry and a write budget): a `GrantOptions`
    /// expiry later than requested, or a budget larger than requested, is refused before anything is signed and the
    /// pairing is not spent; one inside the bounds is approved with it.
    @Test func theCombinedApprovalRefusesToWidenTheRequestsOwnBounds() async throws {
        let clock = TestClock(Self.t0)
        let op = Device(clock: { clock.date })
        await op.session.create()
        try #require(op.session.phase == .ready, "\(describe(op))")
        let account = try #require(op.session.libraryID)
        let member: any AsyncKeyProvider = SoftwareKeys()
        let keys = try await member.publicKeys()
        let requested = Self.date(Self.t0 + 86_400_000)
        let termsJSON = #"{"expires":"\#(requested)","records":[{"access":"write","namespace":"reading.saved"}],"services":[{"audience":"\#(Self.audience)","purposes":["\#(Self.purpose)"]}],"writes":5}"#
        let request = try AccountRequest.prepare(spec: RequestSpec(account: account, signing: keys.signing, agreement: keys.agreement, label: "Bounded rig",
            kind: .app, termsJson: termsJSON, created: try accountFormatDate(ms: Self.t0 - 1000), custody: nil, operator: nil, endpoints: []))
        let signature = try await member.sign(body: try request.step().body)
        let raw = try request.finish(signature: Signature(signature: signature, authenticatorData: nil, clientData: nil)).raw
        let scanned = try await op.session.scanRequest(raw)
        await #expect(throws: SessionError.invalidCommand) {
            try await op.session.approve(scanned.request, pairing: scanned.pairing, services: ServiceGrant(),
                                         grant: GrantOptions(namespaces: nil, access: nil, expires: Self.date(Self.t0 + 2 * 86_400_000), writeBudget: nil))
        }
        await #expect(throws: SessionError.invalidCommand) {
            try await op.session.approve(scanned.request, pairing: scanned.pairing, services: ServiceGrant(),
                                         grant: GrantOptions(namespaces: nil, access: nil, expires: nil, writeBudget: 10))
        }
        #expect(!op.session.members.contains { $0.id == scanned.request.id }, "nothing was granted")
        // The same pairing, never spent, approves inside the bounds.
        let inside = Self.t0 + 3_600_000
        try await op.session.approve(scanned.request, pairing: scanned.pairing, services: ServiceGrant(),
                                     grant: GrantOptions(namespaces: nil, access: nil, expires: Self.date(inside), writeBudget: 3))
        let granted = try #require(op.session.members.first { $0.id == scanned.request.id })
        #expect(granted.expiresMs == inside)
        #expect(granted.grant?.writeBudget == 3)
    }

    @Test func aRigGrantedByTheOperatorProvisionsAFreshAccount() async throws {
        let clock = TestClock(Self.t0)
        let relay = RelayHome(base: "https://door.test/v1/accounts/operator-swift", port: RelayHome.freePort(), clock: { clock.now })
        defer { relay.stop() }
        // The operator account lives on the relay's own slot `home`, which the door names as its operator slot.
        let operatorHome = HomeConfiguration(endpoint: URL(string: relay.base + "/")!, request: { account in
            try relay.start(account: account, provision: Self.provision(account))
            return try relay.memberRequest(account: account)
        }, transport: relay.transport())
        let op = Device(homes: [operatorHome], createWithoutHome: false, clock: { clock.date })
        await op.session.create()
        op.session.stopSync()
        try #require(op.session.phase == .ready, "\(describe(op))")
        try await settle(op, relay, clock)

        // The rig joins the operator account asking for two of the door's purposes, and no namespace.
        let keys = CountingKeys()
        let rig = Device(medium: authorityOnly(op.medium), homes: [HomeConfiguration(endpoint: URL(string: relay.base + "/")!, transport: relay.transport())],
                         createWithoutHome: false, namespaces: [], services: [ServiceTerms(audience: Self.audience, purposes: [Self.purpose, Self.release])],
                         keys: keys, clock: { clock.date })
        await rig.session.restore()
        rig.session.stopSync()
        guard case .waitingForApproval = rig.session.phase else { Issue.record("expected waiting, got \(describe(rig))"); return }
        let scanned = try await op.session.scanRequest(try await rig.session.exportRequest())
        #expect(scanned.request.services == [ServiceTerms(audience: Self.audience, purposes: [Self.purpose, Self.release])])
        #expect(scanned.request.namespaces.isEmpty)
        await #expect(throws: SessionError.invalidCommand) {
            try await op.session.approve(scanned.request, pairing: scanned.pairing,
                                         services: ServiceGrant(services: [ServiceTerms(audience: "https://other.test/v1/provision", purposes: [Self.purpose])]))
        }
        // The grant: provisioning only (release is withheld), until t0 + 240 s, and ci- slots.
        let expires = Self.t0 + 240_000
        let again = try await op.session.scanRequest(try await rig.session.exportRequest())
        try await op.session.approve(again.request, pairing: again.pairing,
                                     services: ServiceGrant(services: [ServiceTerms(audience: Self.audience, purposes: [Self.purpose])], expires: Self.date(expires), conditionsJSON: Self.slotPrefix))
        let rigID = try #require(rig.session.memberID)
        #expect(op.session.members.first { $0.id == rigID }?.expiresMs == expires, "the grant carries its expiry")
        try await settle(op, relay, clock)
        #expect(try await untilApproved(rig, relay, clock), "the rig learns its approval: \(describe(rig))")

        // The signer's own check. A purpose never asked for, or another audience: refused before the key is asked.
        let args = #"{"account":"\#(String(repeating: "ab", count: 32))","base":"\#(Self.prefix)ci-swift-x","slot":"ci-swift-x"}"#
        let signs = keys.signs
        #expect(await refused("refused:outOfScope") { _ = try await rig.session.signCall(audience: Self.audience, purpose: "home.other", argsJSON: args) })
        #expect(await refused("refused:outOfScope") { _ = try await rig.session.signCall(audience: "https://other.test/v1/provision", purpose: Self.purpose, argsJSON: args) })
        #expect(keys.signs == signs, "the key was not asked")
        // A purpose asked for but withheld by the grant: the key signs, the core's check refuses, and no call is returned.
        #expect(await refused("refused:outOfScope") { _ = try await rig.session.signCall(audience: Self.audience, purpose: Self.release, argsJSON: args) })
        #expect(keys.signs == signs + 1, "the key was asked once, and its call was refused")

        // A fresh account whose home request is the rig's provisionRequest: provisioned, written, read on a second device.
        let slot = "ci-swift-\(UUID().uuidString.prefix(8).lowercased())", base = Self.prefix + slot
        let rigSession = rig.session
        let appHome = HomeConfiguration(endpoint: URL(string: base + "/")!, request: { account in
            try await rigSession.provisionRequest(door: relay.door, audience: Self.audience, slot: slot, base: base, account: account, transport: relay.doorTransport())
        }, transport: relay.slotTransport(base: base, slot: slot))
        let app = Device(homes: [appHome], createWithoutHome: false, clock: { clock.date })
        await app.session.create()
        app.session.stopSync()
        try #require(app.session.phase == .ready, "\(describe(app))")
        #expect(app.session.homes.count == 1, "the provisioned home is appointed")
        try await app.session.perform(try .saveLink(id: "a", url: URL(string: "https://example.org/a")!, title: "A"), observed: app.session.observedRevision)
        try await settle(app, relay, clock)
        let second = Device(medium: authorityOnly(app.medium), homes: [HomeConfiguration(endpoint: URL(string: base + "/")!, transport: relay.slotTransport(base: base, slot: slot))],
                            createWithoutHome: false, clock: { clock.date })
        await second.session.restore()
        second.session.stopSync()
        try await approveByScan(joining: second.session, approving: app.session)
        try await settle(app, relay, clock)
        #expect(try await untilApproved(second, relay, clock), "\(describe(second))")
        try await settle(second, relay, clock)
        #expect(try await SavedStore(session: second.session).load(ItemsQuery(limit: 50)).get().total == 1, "the second device reads what the first wrote")

        // A slot outside the grant's prefix: the rig's own check refuses it (the condition is false); nothing is sent.
        #expect(await refused("refused:outOfScope") {
            _ = try await rig.session.provisionRequest(door: relay.door, audience: Self.audience, slot: "other-swift", base: Self.prefix + "other-swift",
                                                       account: String(repeating: "cd", count: 32), transport: relay.doorTransport())
        })
        // The door's own refusal is final: a call for one slot carried with another slot's body is 403, nothing made.
        let call = try await rig.session.signCall(audience: Self.audience, purpose: Self.purpose,
            argsJSON: #"{"account":"\#(String(repeating: "cd", count: 32))","base":"\#(Self.prefix)ci-swift-y","slot":"ci-swift-y"}"#)
        let body = Data(#"{"account":"\#(String(repeating: "cd", count: 32))","base":"\#(Self.prefix)other-swift","slot":"other-swift"}"#.utf8)
        let refusedAnswer = try await relay.doorTransport().send(HttpRequest(ticket: 0, home: "", method: .post, url: relay.door.absoluteString, headers: [
            Header(name: "Content-Type", value: "application/json"), Header(name: "Content-Length", value: String(body.count)),
            Header(name: "Authorization", value: "Colophon \(call)")], body: body))
        #expect(refusedAnswer.status == 403)
        #expect(HomeRefusal(status: refusedAnswer.status, headers: refusedAnswer.headers, body: refusedAnswer.body)?.code == "refused:outOfScope")

        // The operator revokes the rig: the rig, which has not synced the revocation, signs; the door refuses it.
        try await op.session.revoke(memberID: rigID)
        try await settle(op, relay, clock)
        do {
            _ = try await rig.session.provisionRequest(door: relay.door, audience: Self.audience, slot: "ci-swift-z", base: Self.prefix + "ci-swift-z",
                                                       account: String(repeating: "ef", count: 32), transport: relay.doorTransport())
            Issue.record("a revoked rig provisioned")
        } catch let refusal as ProvisionRefusal {
            #expect(refusal.status == 403 && refusal.code == "refused:revoked", "\(refusal)")
        }

        // The clock passes the grant's expiry (the heads the rig holds are still fresh): its own check refuses as expired.
        #expect(clock.now < expires, "the journey ran inside the grant")
        clock.set(expires + 10_000)
        #expect(await refused("refused:expired") { _ = try await rig.session.signCall(audience: Self.audience, purpose: Self.purpose, argsJSON: args) })
    }
}
