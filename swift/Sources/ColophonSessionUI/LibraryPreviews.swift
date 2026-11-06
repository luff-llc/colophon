#if DEBUG
import ColophonSession
import Observation
import SwiftUI

/// UI-only in-memory source. Never opens files, creates keys, or signs records.
@Observable @MainActor final class PreviewLibrarySession: LibrarySessionSource {
    var phase: SessionPhase
    var context = UUID()
    var revision: UInt64 = 1
    var members: [Member]
    var requests: [AccessRequest]
    var ledger: [LedgerEntry]
    init(phase: SessionPhase = .ready) {
        self.phase = phase
        members = [
            Member(id: "owner", label: "My Mac", kind: .device, grant: nil, since: 1, revokedAt: nil, writes: 2),
            Member(id: "reader", label: "Reading Assistant", kind: .agent,
                   grant: Grant(namespaces: ["reading.books"], access: [.read], expires: nil, writeBudget: nil),
                   since: 2, revokedAt: nil, writes: 0)
        ]
        requests = [Self.request]
        ledger = [LedgerEntry(sequence: 1, at: "2026-11-06T12:00:00Z", actor: "owner", actorLabel: "My Mac",
                              event: .created, subject: nil, namespace: nil, kind: nil, origin: nil, text: "Created this library")]
    }
    static let request = AccessRequest(id: "request", label: "My iPad", kind: .device,
                                      namespaces: ["reading.books", "notes"], access: [.read, .write],
                                      pairingCode: "123456", record: Data())
    func restore() async {}
    func refresh() async {}
    func retry() async {}
    func create() async { phase = .ready }
    func leave() async throws { phase = .noLibrary; context = UUID() }
    func rejoin(keys: any AsyncKeyProvider) async { phase = .waitingForApproval(code: "123456") }
    func importRequest(from url: URL) async throws {}
    func approve(_ request: AccessRequest, grant: GrantOptions?) async throws { requests.removeAll { $0.id == request.id }; revision += 1 }
    func revoke(memberID: String) async throws { revision += 1 }
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
#Preview("Pairing") { GatePreview(.waitingForApproval(code: "123456")) }
#Preview("Access ended") { GatePreview(.denied) }
#Preview("Unavailable") { GatePreview(.unavailable(reason: "The library folder is offline. Make it available on this device, then retry.")) }
#Preview("Upgrading") { GatePreview(.migrating) }
#Preview("Key failure") { GatePreview(.failed(error: .keysUnavailable(detail: "Unlock your device."))) }
#Preview("Other failure") { GatePreview(.failed(error: .other(detail: "The library could not be opened."))) }
#Preview("Ready · settings") { GatePreview(.ready) }
#Preview("Approve · large text") {
    NavigationStack { ApproveRequestView(request: PreviewLibrarySession.request, session: PreviewLibrarySession()) }
        .environment(\.dynamicTypeSize, .accessibility3)
}
#Preview("Member") { NavigationStack { MemberDetailView(member: PreviewLibrarySession().members[1], session: PreviewLibrarySession()) } }
#Preview("Colophon") { NavigationStack { ColophonLedgerView(session: PreviewLibrarySession()) } }
#Preview("Connect") { NavigationStack { ConnectLibraryView(host: PreviewLibrarySession.host) } }
#Preview("Join") { NavigationStack { ConnectLibraryView(host: PreviewLibrarySession.host, purpose: .join) } }
#Preview("Recovery") { NavigationStack { RecoveryKitView(host: PreviewLibrarySession.host) } }
#Preview("Support") { NavigationStack { SupportReportView(session: PreviewLibrarySession()) } }
#endif
