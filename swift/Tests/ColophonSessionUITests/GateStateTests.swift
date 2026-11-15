import Foundation
import Observation
import SwiftUI
import Testing
import ColophonSession
@testable import ColophonSessionUI

/// A deterministic session source: it never opens a file or a key, it only publishes values.
@Observable @MainActor private final class FakeSession: LibrarySessionSource {
    var phase: SessionPhase
    var context = UUID()
    var revision: UInt64 = 1
    var members: [AccountMember] = []
    var requests: [AccessRequest] = []
    var notices: SessionNotices = .empty
    var vetoed: [String] = []
    var acknowledged = 0
    var unlocked = 0
    init(_ phase: SessionPhase) { self.phase = phase }
    func restore() async {}
    func refresh() async {}
    func retry() async {}
    func create() async {}
    func leave() async throws {}
    func rejoin(keys: any AsyncKeyProvider) async {}
    func importRequest(from url: URL) async throws {}
    func approve(_ request: AccessRequest, grant: GrantOptions?) async throws {}
    func revoke(memberID: String) async throws {}
    func veto(_ transition: String) async throws { vetoed.append(transition) }
    func acknowledgeNotices() async { acknowledged += 1; notices = .empty }
    func unlock() async { unlocked += 1; phase = .ready }
}

private func pending(vetoable: Bool = true) -> Pending {
    Pending(digest: String(repeating: "ab", count: 32), by: "11111111111111111111111111111111",
            signers: [Signer(id: "22222222222222222222222222222222", label: "Laptop")], issuedMs: 1_000, anchorSeq: 4, firstSeenSeq: 4,
            dueMs: 260_000_000, vetoDeadlineMs: 259_000_000, fullSet: false, components: ["homes"], removes: [], adds: [], vetoes: [], vetoable: vetoable)
}
private func activation() -> SeenActivation {
    SeenActivation(seq: 7, transition: String(repeating: "cd", count: 32), signers: ["33333333333333333333333333333333"], components: ["keyring"],
                   receipted: [Receipted(home: "44444444444444444444444444444444", receivedMs: 5)])
}

@MainActor struct GateStateTests {
    private func render<V: View>(_ view: V) -> Bool { ImageRenderer(content: view.frame(width: 390, height: 700)).cgImage != nil }

    @Test func everyPhaseTheGateCanShowRenders() {
        let phases: [SessionPhase] = [.opening, .noLibrary, .creating, .migrating, .waitingForDownload, .waitingForApproval(code: "ABCD-1234"), .denied,
            .unavailable(reason: "offline"), .updateRequired, .ready, .refreshing, .retry, .locked, .failed(error: .keysUnavailable(detail: "locked")), .failed(error: .other(detail: "x"))]
        for phase in phases {
            let session = FakeSession(phase)
            #expect(render(LibraryGate(session: session, presentation: .init(appName: "Later", promise: "Keep it."), content: { Text("content") })), "\(phase)")
        }
    }

    @Test func pendingChangesUnseenActivationsAndTheNoHomeWarningRender() {
        let session = FakeSession(.ready)
        session.notices = SessionNotices(notices: Notices(pending: [pending()], activations: [activation()], owed: [], controllersWithoutSlot: [], vaultRetiring: false, noHome: true))
        #expect(render(NoticesView(session: session)))
        #expect(render(LibraryGate(session: session, presentation: .init(appName: "Later", promise: "Keep it."), content: { Text("content") })))
    }

    @Test func theWordsSayWhatTheSpecificationAsksTheHostToSay() {
        #expect(NoticeWords.noHome.contains("no home") && NoticeWords.noHome.contains("Add a home"))
        #expect(NoticeWords.waiting.hasPrefix("Waiting protects who controls your account."))
        #expect(NoticeWords.oneDevice.contains("stolen"))
        #expect(NoticeWords.vetoDeadline(nil).contains("not known"))
        #expect(NoticeWords.vetoDeadline(259_000_000).hasPrefix("You can say no until"))
    }

    @Test func theVetoIsOneCallAndAnUnlockOpensTheLockedGate() async throws {
        let session = FakeSession(.locked)
        let model = LibraryActionModel()
        await model.run { try await session.veto(pending().digest) }
        #expect(session.vetoed == [pending().digest] && model.error == nil)
        await model.run { await session.unlock() }
        #expect(session.unlocked == 1 && session.phase == .ready)
        session.notices = SessionNotices(notices: Notices(pending: [], activations: [activation()], owed: [], controllersWithoutSlot: [], vaultRetiring: false, noHome: false))
        #expect(session.notices.unseenActivations.count == 1)
        await session.acknowledgeNotices()
        #expect(session.notices.unseenActivations.isEmpty && session.acknowledged == 1)
    }

    @Test func aRequestShowsItsNamespacesAndAccessAndTheSupportReportNamesTheLockedPhase() throws {
        let request = AccessRequest(id: "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a", label: "iPad", kind: .device,
            termsJSON: #"{"records":[{"namespace":"reading.saved","access":"write"},{"namespace":"notes","access":"read"}]}"#, record: Data())
        #expect(request.namespaces == ["reading.saved", "notes"] && request.access == [.read, .write])
        #expect(request.pairingCode == "5A5A-5A5A")
        let report = try SupportReport(session: FakeSession(.locked)).text()
        #expect(report.contains("\"phase\" : \"locked\""))
        #expect(!report.contains("5a5a"), "the report carries no identifiers")
    }

    @Test func memberWordsDescribeGrantsAndKinds() {
        let member = AccountMember(id: "m", label: "Mac", kind: .app, kindRaw: nil,
            grant: AccountGrant(namespaces: ["reading.saved"], access: [.read, .write], expires: nil, writeBudget: 5, import: false),
            since: 3, revokedAt: nil, writes: 2, expiresMs: nil, provisional: false, home: false, session: 0)
        #expect(LibraryWords.grant(member).contains("Read and change") && LibraryWords.grant(member).contains("Up to 5 changes; 2 made"))
        #expect(LibraryWords.kind(AccountMemberKind.unknown) == "Unknown kind")
    }
}
