import ColophonSession
import SwiftUI
import UniformTypeIdentifiers

/// Embed in a NavigationStack. Supply the same host actions as LibraryGate.
public struct LibrarySettingsView: View {
    let session: any LibrarySessionSource
    let host: LibraryHostActions
    @State private var action = LibraryActionModel()
    @State private var scanned: ScannedRequest?
    @State private var confirmsLeave = false
    public init(session: any LibrarySessionSource, host: LibraryHostActions = .init()) {
        self.session = session; self.host = host
    }
    public var body: some View {
        Form {
            Section {
                Label("Your Library", systemImage: "books.vertical.fill").font(.title2.bold())
                Text("Your devices keep the library. Your keys decide who has access.").foregroundStyle(.secondary)
            }
            if session.phase == .ready {
                Section("Requests to Join") {
                    if let scan = host.scanRequest {
                        Button("Scan a Request to Join", systemImage: "qrcode.viewfinder") {
                            Task { await action.run { scanned = try await session.scanRequest(try await scan()) } }
                        }
                        .accessibilityIdentifier("library.request.scan")
                    }
                    // A request listed here is not approved from the list: approving needs the requesting device
                    // itself, by scanning its screen or by comparing the six-digit code (spec §9.1).
                    ForEach(session.requests, id: \.id) { request in
                        VStack(alignment: .leading) {
                            Text(request.label)
                            Text("\(LibraryWords.kind(request.kind)) · Scan this device's request to review it").foregroundStyle(.secondary)
                        }.accessibilityIdentifier("library.request.\(request.id)")
                    }
                    if session.requests.isEmpty { Text("No requests waiting").foregroundStyle(.secondary) }
                }
                Section("Members") {
                    ForEach(session.members, id: \.id) { member in
                        NavigationLink {
                            MemberDetailView(member: member, session: session)
                        } label: {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(member.label).font(.headline)
                                Text(LibraryWords.kind(member.kind)).foregroundStyle(.secondary)
                                Text(LibraryWords.grant(member)).font(.subheadline).foregroundStyle(.secondary)
                            }
                        }.accessibilityIdentifier("library.member.\(member.id)")
                    }
                }
                Section {
                    NavigationLink { ConnectLibraryView(host: host) } label: { Label("Connect Another Device", systemImage: "plus.rectangle.on.rectangle") }
                        .accessibilityIdentifier("library.addDevice")
                }
            } else {
                Section {
                    Text("The library is not ready. Return to the welcome screen to check access or retry.")
                    Button("Retry") { Task { await action.run { await session.retry() } } }.accessibilityIdentifier("library.retry")
                }
            }
            Section {
                NavigationLink { RecoveryKitView(host: host) } label: { Label("Recovery Kit", systemImage: "key.horizontal") }
                    .accessibilityIdentifier("library.recovery.open")
                NavigationLink { SupportReportView(session: session) } label: { Label("Support Report", systemImage: "ladybug") }
                    .accessibilityIdentifier("library.bugReport")
            }
            Section {
                if session.phase != .noLibrary {
                    Button("Leave This Library", role: .destructive) { confirmsLeave = true }
                        .accessibilityIdentifier("library.leaveFromSettings")
                }
                if host.rejoinKeys != nil {
                    Button("Rejoin Library") { Task { await action.rejoin(session: session, host: host) } }
                        .accessibilityIdentifier("library.rejoin")
                }
            } footer: { Text(LibraryWords.leaving) }
            if action.isWorking { ProgressView("Updating library") }
            LibraryErrorView(message: action.error)
        }
        .formStyle(.grouped).navigationTitle("Library")
        .disabled(action.isWorking)
        .accessibilityIdentifier("library.settings")
        .navigationDestination(item: Binding(get: { scanned.map(ScannedItem.init) }, set: { scanned = $0?.scanned })) { item in
            ApproveRequestView(scanned: item.scanned, session: session)
        }
        .confirmationDialog("Leave this library?", isPresented: $confirmsLeave, titleVisibility: .visible) {
            Button("Leave Library", role: .destructive) { Task { await action.run { try await session.leave() } } }
                .accessibilityIdentifier("library.leave.confirm")
            Button("Cancel", role: .cancel) {}.accessibilityIdentifier("library.leave.cancel")
        } message: { Text(LibraryWords.leaving) }
    }
}

/// A scanned request as a navigation item, identified by the member it would admit.
private struct ScannedItem: Hashable, Identifiable {
    let scanned: ScannedRequest
    var id: String { scanned.request.id }
    static func == (a: ScannedItem, b: ScannedItem) -> Bool { a.id == b.id }
    func hash(into hasher: inout Hasher) { hasher.combine(id) }
}
