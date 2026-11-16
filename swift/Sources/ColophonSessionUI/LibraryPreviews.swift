#if DEBUG
import ColophonSession
import Observation
import SwiftUI

/// UI-only in-memory source. Never opens files, creates keys, or signs records.
@Observable @MainActor final class PreviewLibrarySession: LibrarySessionSource {
    var phase: SessionPhase
    var context = UUID()
    var revision: UInt64 = 1
    var members: [AccountMember]
    var requests: [AccessRequest]
    var notices: SessionNotices = .empty
    init(phase: SessionPhase = .ready) {
        self.phase = phase
        members = [
            Self.member("device", "My Mac", .device, ["notes", "reading.books"], [.read, .write]),
            Self.member("reader", "Reading Assistant", .agent, ["reading.books"], [.read]),
        ]
        requests = [Self.request]
    }
    static func member(_ id: String, _ label: String, _ kind: AccountMemberKind, _ namespaces: [String], _ access: [AccessKind]) -> AccountMember {
        AccountMember(id: id, label: label, kind: kind, kindRaw: nil, grant: AccountGrant(namespaces: namespaces, access: access, expires: nil, writeBudget: nil, import: false),
                      since: 3, revokedAt: nil, writes: 0, expiresMs: nil, provisional: false, home: false, session: 0, grantedBy: [])
    }
    static let request = AccessRequest(id: "request", label: "My iPad", kind: .device,
        termsJSON: #"{"records":[{"namespace":"reading.books","access":"write"},{"namespace":"notes","access":"write"}]}"#, record: Data())
    func restore() async {}
    func refresh() async {}
    func retry() async {}
    func create() async { phase = .ready }
    func leave() async throws { phase = .noLibrary; context = UUID() }
    func rejoin(keys: any AsyncKeyProvider) async { phase = .waitingForApproval }
    func scanRequest(_ data: Data) async throws -> ScannedRequest { throw SessionError.notReady }
    func rejectPairing(_ pairing: AccountPairing) async throws {}
    func approve(_ request: AccessRequest, pairing: AccountPairing, grant: GrantOptions?) async throws { requests.removeAll { $0.id == request.id }; revision += 1 }
    func revoke(memberID: String) async throws { revision += 1 }
    func veto(_ transition: String) async throws { notices = .empty }
    func acknowledgeActivation(seq: UInt64) async {
        notices = SessionNotices(notices: Notices(pending: notices.pending, activations: notices.unseenActivations.filter { $0.seq != seq }, owed: notices.owed,
                                                  controllersWithoutSlot: notices.notices.controllersWithoutSlot, vaultRetiring: notices.notices.vaultRetiring, noHome: notices.noHome))
    }
    func unlock() async { phase = .ready }
    func lock() async { phase = .locked }
    var duties: HostDuties = .none
    func resign(_ transition: String) async throws -> String { transition }
    func removeFollowUp(seq: UInt64) async throws {}
    func keepFollowUp(seq: UInt64) async throws {}
    static var host: LibraryHostActions {
        .init(containers: [
            .init(id: "cloud", title: "iCloud Drive", kind: .iCloud, location: .iCloud(container: "preview", libraryName: "Library")),
            .init(id: "suite", title: "Apps on This Device", kind: .appGroup, location: .appGroup(identifier: "preview", libraryName: "Library"))
        ], connect: { _, _ in }, exportRecoveryKit: { "PREVIEW ONLY — not a recovery key" }, importRecoveryKit: { _ in })
    }
}

private struct GatePreview: View {
    @State var session: PreviewLibrarySession
    init(_ phase: SessionPhase) { _session = State(initialValue: PreviewLibrarySession(phase: phase)) }
    var body: some View {
        LibraryGate(session: session, presentation: .init(appName: "Shelf", promise: "Keep the books that stay with you."),
                    host: PreviewLibrarySession.host, migrationProgress: 0.42) {
            Image(systemName: "books.vertical.fill").font(.largeTitle).foregroundStyle(.tint)
        } content: {
            NavigationStack { LibrarySettingsView(session: session, host: PreviewLibrarySession.host) }
        }
    }
}

#Preview("Opening") { GatePreview(.opening) }
#Preview("Welcome · light") { GatePreview(.noLibrary).preferredColorScheme(.light) }
#Preview("Welcome · dark · large text") { GatePreview(.noLibrary).preferredColorScheme(.dark).environment(\.dynamicTypeSize, .accessibility3) }
#Preview("Creating") { GatePreview(.creating) }
#Preview("Pairing") { GatePreview(.waitingForApproval) }
#Preview("Access ended") { GatePreview(.denied) }
#Preview("Unavailable") { GatePreview(.unavailable(reason: "The library folder is offline. Make it available on this device, then retry.")) }
#Preview("Upgrading") { GatePreview(.migrating) }
#Preview("Key failure") { GatePreview(.failed(error: .keysUnavailable(detail: "Unlock your device."))) }
#Preview("Other failure") { GatePreview(.failed(error: .other(detail: "The library could not be opened."))) }
#Preview("Ready · settings") { GatePreview(.ready) }
#Preview("Approve · large text") {
    // A preview pairing on the code path (a joining device's session; the preview never approves).
    let pairing = try! AccountPairing.join(account: String(repeating: "ab", count: 32),
                                           e: try! PairingTransferKey.create(entropy: Data(repeating: 1, count: 32)).public(),
                                           nb: Data(repeating: 2, count: 32))
    NavigationStack { ApproveRequestView(request: PreviewLibrarySession.request, pairing: pairing, code: "123456", session: PreviewLibrarySession()) }
        .environment(\.dynamicTypeSize, .accessibility3)
}
#Preview("Member") { NavigationStack { MemberDetailView(member: PreviewLibrarySession().members[1], session: PreviewLibrarySession()) } }
#Preview("Connect") { NavigationStack { ConnectLibraryView(host: PreviewLibrarySession.host) } }
#Preview("Join") { NavigationStack { ConnectLibraryView(host: PreviewLibrarySession.host, purpose: .join) } }
#Preview("Recovery") { NavigationStack { RecoveryKitView(host: PreviewLibrarySession.host) } }
#Preview("Support") { NavigationStack { SupportReportView(session: PreviewLibrarySession()) } }
#endif
