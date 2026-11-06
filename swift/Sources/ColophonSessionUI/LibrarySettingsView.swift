import ColophonSession
import SwiftUI
import UniformTypeIdentifiers

/// Embed in a NavigationStack. Supply the same host actions as LibraryGate.
public struct LibrarySettingsView: View {
    let session: any LibrarySessionSource
    let host: LibraryHostActions
    @State private var action = LibraryActionModel()
    @State private var importing = false
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
                    Button("Import Pairing Request…", systemImage: "person.badge.plus") { importing = true }
                        .accessibilityIdentifier("library.request.import")
                    ForEach(session.requests, id: \.id) { request in
                        NavigationLink {
                            ApproveRequestView(request: request, session: session)
                        } label: {
                            VStack(alignment: .leading) {
                                Text(request.label)
                                Text("\(LibraryWords.kind(request.kind)) · Review access").foregroundStyle(.secondary)
                            }
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
                    NavigationLink { ColophonLedgerView(session: session) } label: { Label("Colophon", systemImage: "text.book.closed") }
                        .accessibilityIdentifier("library.ledger.open")
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
        .fileImporter(isPresented: $importing, allowedContentTypes: [.json]) { result in
            switch result {
            case .success(let url): Task { await action.run { try await session.importRequest(from: url) } }
            case .failure(let error): action.report(error)
            }
        }
        .confirmationDialog("Leave this library?", isPresented: $confirmsLeave, titleVisibility: .visible) {
            Button("Leave Library", role: .destructive) { Task { await action.run { try await session.leave() } } }
                .accessibilityIdentifier("library.leave.confirm")
            Button("Cancel", role: .cancel) {}.accessibilityIdentifier("library.leave.cancel")
        } message: { Text(LibraryWords.leaving) }
    }
}
