import ColophonSession
@testable import ColophonSessionUI
import Foundation
import Observation
import Testing

@Observable @MainActor final class TestSession: LibrarySessionSource {
    var phase: SessionPhase = .ready
    var context = UUID()
    var revision: UInt64 = 1
    var members: [Member] = []
    var requests = [AccessRequest(id: "request-private", label: "Private device name", kind: .agent,
                                 namespaces: ["notes", "reading.books"], access: [.read, .write], pairingCode: "secret-code", record: Data("private-record".utf8))]
    var ledger: [LedgerEntry] = []
    var approved: GrantOptions?
    var approvals = 0
    var rejoined = false
    var refreshAction: (() -> Void)?
    var failure: (any Error)?
    func restore() async {}
    func refresh() async { refreshAction?() }
    func retry() async {}
    func create() async { phase = .ready }
    func leave() async throws { if let failure { throw failure }; phase = .noLibrary }
    func rejoin(keys: any AsyncKeyProvider) async { rejoined = true; phase = .waitingForApproval(code: "new-code") }
    func importRequest(from url: URL) async throws { if let failure { throw failure } }
    func approve(_ request: AccessRequest, grant: GrantOptions?) async throws {
        if let failure { throw failure }; approvals += 1; approved = grant
    }
    func revoke(memberID: String) async throws { if let failure { throw failure } }
}

@MainActor struct ApprovalModelTests {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    @Test func requiresCodeComparison() throws {
        let session = TestSession()
        let model = ApprovalModel(request: session.requests[0], session: session)
        #expect(throws: (any Error).self) { try model.grant() }
    }
    @Test func narrowsEveryGrantDimension() async throws {
        let session = TestSession()
        let model = ApprovalModel(request: session.requests[0], session: session, now: now)
        model.codeMatches = true; model.namespaces = ["notes"]
        model.limitsExpiry = true; model.expires = now.addingTimeInterval(60)
        model.limitsBudget = true; model.budget = "4"
        #expect(await model.approve(session: session, now: now))
        let grant = try #require(session.approved)
        #expect(grant.namespaces == ["notes"])
        #expect(grant.access == [.read, .write])
        #expect(grant.expires == model.expires.ISO8601Format())
        #expect(grant.writeBudget == 4)
    }
    @Test func readOnlyDropsWriteBudget() throws {
        let session = TestSession()
        let model = ApprovalModel(request: session.requests[0], session: session)
        model.codeMatches = true; model.readOnly = true; model.limitsBudget = true; model.budget = "not a number"
        let grant = try model.grant()
        #expect(grant.access == [.read]); #expect(grant.writeBudget == nil)
    }
    @Test(arguments: [Set<String>(), Set(["not-requested"])])
    func refusesEmptyOrBroaderNamespaces(namespaces: Set<String>) throws {
        let session = TestSession()
        let model = ApprovalModel(request: session.requests[0], session: session)
        model.codeMatches = true; model.namespaces = namespaces
        #expect(throws: (any Error).self) { try model.grant() }
    }
    @Test(arguments: ["0", "-1", "1.5", "18446744073709551616", ""])
    func rejectsInvalidBudget(budget: String) throws {
        let session = TestSession()
        let model = ApprovalModel(request: session.requests[0], session: session)
        model.codeMatches = true; model.limitsBudget = true; model.budget = budget
        #expect(throws: (any Error).self) { try model.grant() }
    }
    @Test func refusesPastExpiry() throws {
        let session = TestSession()
        let model = ApprovalModel(request: session.requests[0], session: session, now: now)
        model.codeMatches = true; model.limitsExpiry = true; model.expires = now
        #expect(throws: (any Error).self) { try model.grant(now: now) }
    }
    @Test func neverAddsWriteToReadRequest() throws {
        let session = TestSession()
        let request = AccessRequest(id: "r", label: "Reader", kind: .server, namespaces: ["notes"], access: [.read], pairingCode: "123", record: Data())
        let model = ApprovalModel(request: request, session: session)
        model.codeMatches = true; model.readOnly = false
        #expect(try model.grant().access == [.read])
    }
    @Test(arguments: ["revision", "context", "request", "phase"])
    func refusesStaleReview(change: String) async {
        let session = TestSession()
        let model = ApprovalModel(request: session.requests[0], session: session)
        model.codeMatches = true
        session.refreshAction = {
            switch change {
            case "revision": session.revision += 1
            case "context": session.context = UUID()
            case "request": session.requests = []
            default: session.phase = .denied
            }
        }
        #expect(await model.approve(session: session) == false)
        #expect(session.approvals == 0); #expect(model.action.error != nil)
    }
    @Test func authorityRefusalRemainsVisible() async {
        let session = TestSession(); session.failure = SessionError.notReady
        let model = ApprovalModel(request: session.requests[0], session: session); model.codeMatches = true
        #expect(await model.approve(session: session) == false)
        #expect(model.action.error != nil); #expect(!model.action.isWorking)
    }
}

@MainActor struct LibraryActionTests {
    @Test func cancellationIsNotAnError() async {
        let action = LibraryActionModel()
        #expect(await action.run { throw CancellationError() } == false)
        #expect(action.error == nil); #expect(!action.isWorking)
    }
    @Test func repeatedGestureCannotReenter() async {
        let action = LibraryActionModel()
        var nestedRan = false
        var nestedResult = true
        let completed = await action.run {
            nestedResult = await action.run { nestedRan = true }
        }
        #expect(completed); #expect(!nestedResult)
        #expect(!nestedRan)
    }
    @Test func keyProviderFailureDoesNotRejoinOrReplaceIdentity() async {
        let session = TestSession()
        let context = session.context
        let action = LibraryActionModel()
        let host = LibraryHostActions(rejoinKeys: { throw SessionError.notReady })
        #expect(await action.rejoin(session: session, host: host) == false)
        #expect(!session.rejoined); #expect(session.context == context)
    }
    @Test func rejoinUsesExplicitProvider() async {
        let session = TestSession()
        let action = LibraryActionModel()
        #expect(await action.rejoin(session: session, host: .init(rejoinKeys: { SoftwareKeys() })))
        #expect(session.rejoined)
        #expect(session.phase == .waitingForApproval(code: "new-code"))
    }
}

@MainActor struct RecoveryModelTests {
    @Test func exportAndClear() async {
        let model = RecoveryKitModel()
        await model.prepare(host: .init(exportRecoveryKit: { "private kit" }))
        #expect(model.exported == "private kit"); #expect(!model.kept)
        model.input = "secret"; model.kept = true; model.clear()
        #expect(model.exported == nil); #expect(model.input.isEmpty); #expect(!model.kept)
    }
    @Test func failedImportDoesNotClaimSuccessOrEchoSecrets() async {
        let model = RecoveryKitModel(); model.input = "TOP SECRET"
        await model.recover(host: .init(importRecoveryKit: { secret in throw LibraryUIError.unavailable(secret) }))
        #expect(!model.imported)
        #expect(model.action.error?.contains("TOP SECRET") == false)
    }
    @Test func importClearsSecretOnlyAfterSuccess() async {
        let model = RecoveryKitModel(); model.input = " private kit "
        var received = ""
        await model.recover(host: .init(importRecoveryKit: { received = $0 }))
        #expect(received == "private kit"); #expect(model.input.isEmpty); #expect(model.imported)
    }
    @Test func emptyAndOversizeSecretsNeverReachProvider() async {
        for secret in ["  ", String(repeating: "x", count: 65537)] {
            let model = RecoveryKitModel(); model.input = secret
            var called = false
            await model.recover(host: .init(importRecoveryKit: { _ in called = true }))
            #expect(!called); #expect(!model.imported)
        }
    }
    @Test func disappearanceDiscardsPendingExport() async {
        let model = RecoveryKitModel()
        await model.prepare(host: .init(exportRecoveryKit: { model.clear(); return "private kit" }))
        #expect(model.exported == nil); #expect(model.action.error == nil)
    }
}

@MainActor struct SupportReportTests {
    @Test(arguments: [SessionPhase.opening, .noLibrary, .creating, .migrating, .waitingForApproval(code: "TOP SECRET"), .denied,
                      .unavailable(reason: "/private/secret"), .ready, .failed(error: .keysUnavailable(detail: "KEY SECRET")),
                      .failed(error: .other(detail: "PRIVATE ERROR"))])
    func allowlistNeverExportsSessionSecrets(phase: SessionPhase) throws {
        let session = TestSession(); session.phase = phase
        let text = try SupportReport(session: session).text()
        for secret in ["TOP SECRET", "/private", "KEY SECRET", "PRIVATE ERROR", "Private device", "secret-code", "private-record", "request-private"] {
            #expect(!text.contains(secret))
        }
        let data = try #require(text.data(using: .utf8))
        let object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(Set(object.keys).isSubset(of: ["schema", "phase", "failureCategory", "memberCount", "requestCount", "ledgerEntryCount", "system"]))
    }
}

@MainActor struct ConnectionModelTests {
    @Test func forwardsLocationAndPurposeAfterExplicitSelection() async {
        let model = ConnectionModel()
        let url = URL(fileURLWithPath: "/tmp/selected-library")
        var received = false
        await model.connect(.folder(url), purpose: .join, host: .init(connect: { purpose, location in
            if case .join = purpose, case .folder(let selected) = location { received = selected == url }
        }))
        #expect(received); #expect(model.completed)
        #expect(model.nextStep.contains("this device’s pairing code"))
    }
    @Test func appGroupInstructionsStayOnThisDevice() async {
        let model = ConnectionModel()
        await model.connect(.appGroup(identifier: "suite", libraryName: "Library"), purpose: .connectAnotherDevice,
                            host: .init(connect: { _, _ in }))
        #expect(model.completed)
        #expect(model.nextStep.contains("other app on this device"))
        #expect(!model.nextStep.contains("other device"))
    }
    @Test func failedConnectionNeverClaimsCompletion() async {
        let model = ConnectionModel()
        await model.connect(.appGroup(identifier: "missing", libraryName: "Library"), purpose: .connectAnotherDevice,
                            host: .init(connect: { _, _ in throw SessionError.destinationChanged }))
        #expect(!model.completed); #expect(model.action.error != nil)
    }
    @Test func unconfiguredConnectionIsExplicit() async {
        let model = ConnectionModel()
        await model.connect(.memory(MemoryRecordStore()), purpose: .join, host: .init())
        #expect(!model.completed); #expect(model.action.error != nil)
    }
}

@MainActor struct MemberAccessTests {
    func member(grant: Grant? = .init(namespaces: ["notes"], access: [.read], expires: nil, writeBudget: nil)) -> Member {
        Member(id: "reader", label: "Reader", kind: .app, grant: grant, since: 1, revokedAt: nil, writes: 0)
    }
    @Test func staleRevocationDoesNotProceed() async {
        let session = TestSession(); let member = member(); session.members = [member]
        let model = MemberAccessModel(member: member, session: session)
        session.refreshAction = { session.revision += 1 }
        #expect(await model.revoke(session: session) == false)
        #expect(model.action.error == SessionError.staleRevision.localizedDescription)
    }
    @Test func ownerIsNotRevocableHere() async {
        let session = TestSession(); let member = member(grant: nil); session.members = [member]
        let model = MemberAccessModel(member: member, session: session)
        #expect(await model.revoke(session: session) == false)
    }
    @Test func refusalDoesNotClaimSuccess() async {
        let session = TestSession(); let member = member(); session.members = [member]
        session.failure = SessionError.notReady
        let model = MemberAccessModel(member: member, session: session)
        #expect(await model.revoke(session: session) == false)
        #expect(model.action.error != nil)
    }
    @Test func memberWordsDescribeKindAndRestrictions() {
        let member = Member(id: "agent", label: "Agent", kind: .agent,
                            grant: .init(namespaces: ["notes"], access: [.read], expires: "2026-12-01T12:00:00Z", writeBudget: 5),
                            since: 1, revokedAt: nil, writes: 3)
        #expect(LibraryWords.kind(member.kind) == "AI agent")
        let summary = LibraryWords.grant(member)
        #expect(summary.contains("Read only")); #expect(summary.contains("Notes"))
        #expect(summary.contains("Expires")); #expect(summary.contains("5 changes; 3 made"))
        #expect(LibraryWords.revocation.contains("Past contributions stay attributed"))
    }
}
