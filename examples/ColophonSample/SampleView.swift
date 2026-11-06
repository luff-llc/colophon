import SwiftUI
import UniformTypeIdentifiers
import ColophonSession

struct SampleView: View {
    let session: ColophonSession
    @State private var links: NamespaceStore<SavedLinksQuery, [SavedLink]>
    @State private var address = "https://example.com"
    @State private var title = "Example"
    @State private var error: String?
    @State private var importing = false
    @Environment(\.scenePhase) private var scenePhase
    private let query = SavedLinksQuery()
    init(session: ColophonSession) {
        self.session = session
        _links = State(initialValue: NamespaceStore(savedLinksIn: session))
    }
    var body: some View {
        NavigationStack {
            Group {
                switch session.phase {
                case .opening, .creating: ProgressView("Opening library…")
                case .noLibrary:
                    ContentUnavailableView {
                        Label("Your library", systemImage: "books.vertical")
                    } description: {
                        Text("Create a library, save a link, and invite an agent with its own identity.")
                    } actions: {
                        Button("Create library") { Task { await session.create() } }
                    }
                case .waitingForApproval(let code):
                    ContentUnavailableView("Waiting for approval", systemImage: "person.badge.key", description: Text("Compare pairing code \(code) with the library owner."))
                case .denied:
                    ContentUnavailableView("Access denied", systemImage: "lock", description: Text("This identity is revoked, expired, or lacks the requested scope."))
                case .unavailable(let reason): recoveryView(reason)
                case .failed(let reason): recoveryView(reason)
                case .ready: libraryView
                }
            }
            .navigationTitle("Colophon")
            .task(id: session.namespaceRevisions["reading.saved"]) { await warmLinks() }
            .onChange(of: session.phase) { _, phase in
                if phase == .ready { Task { await warmLinks() } }
            }
            .onChange(of: scenePhase) { _, phase in
                if phase == .active { Task { await session.refresh() } }
            }
            .fileImporter(isPresented: $importing, allowedContentTypes: [.json]) { result in
                Task {
                    do { try await session.importRequest(from: result.get()) }
                    catch { self.error = error.localizedDescription }
                }
            }
            .alert("Couldn’t finish", isPresented: Binding(get: { error != nil }, set: { if !$0 { error = nil } })) {
                Button("OK") { error = nil }
            } message: { Text(error ?? "") }
        }
        .frame(minWidth: 320, minHeight: 480)
    }
    private var libraryView: some View {
        List {
            Section("Save a link") {
                TextField("URL", text: $address)
                    .accessibilityIdentifier("linkURL")
                TextField("Title", text: $title)
                Button("Save link", systemImage: "plus") {
                    let observed = session.observedRevision
                    Task {
                        do {
                            guard let url = URL(string: address) else { throw SessionError.invalidCommand }
                            let receipt = try await session.perform(.saveLink(url: url, title: title), observed: observed)
                            if receipt == .queued { error = "Queued for retry. The link is not saved yet." }
                        } catch { self.error = error.localizedDescription }
                    }
                }
            }
            Section("Saved links") {
                if links.state == .warming { ProgressView() }
                ForEach(links.cached(query) ?? []) { link in SavedLinkRow(link: link) }
            }
            Section("Invite an agent") {
                Text("Ask the agent to create a signed pairing request for this library, then import its JSON file. Compare the displayed code before approving.")
                Text(session.libraryID ?? "").font(.caption.monospaced()).textSelection(.enabled)
                Button("Import pairing request", systemImage: "person.badge.plus") { importing = true }
                ForEach(session.requests, id: \.id) { request in
                    PairingRow(request: request) {
                        Task { do { try await session.approve(request) } catch { self.error = error.localizedDescription } }
                    }
                }
            }
            Section("Members") {
                ForEach(session.members, id: \.id) { member in
                    MemberRow(member: member, canRevoke: member.grant != nil && member.revokedAt == nil) {
                        Task { do { try await session.revoke(memberID: member.id) } catch { self.error = error.localizedDescription } }
                    }
                }
            }
            Section("Colophon ledger") {
                // Capturing the cached array is O(1); each row receives a plain value.
                let entries = session.ledger
                ForEach(entries.indices, id: \.self) { index in LedgerRow(entry: entries[index]) }
            }
        }
    }
    private func recoveryView(_ reason: String) -> some View {
        ContentUnavailableView {
            Label("Library unavailable", systemImage: "externaldrive.badge.exclamationmark")
        } description: { Text(reason) } actions: {
            Button("Retry") { Task { await session.refresh() } }
        }
    }
    private func warmLinks() async {
        guard session.phase == .ready else { return }
        do { try await links.load(query) } catch { self.error = error.localizedDescription }
    }
}

private struct SavedLinkRow: View {
    let link: SavedLink
    var body: some View { VStack(alignment: .leading) { Text(link.title ?? link.url); Text(link.url).font(.caption).foregroundStyle(.secondary) } }
}
private struct PairingRow: View {
    let request: AccessRequest
    let approve: () -> Void
    var body: some View {
        VStack(alignment: .leading) {
            Text(request.label)
            Text("\(String(describing: request.kind).capitalized) · \(request.access.contains(.write) ? "Read and write" : "Read only")").font(.caption)
            Text("Pairing code: \(request.pairingCode)").monospaced()
            Text(request.namespaces.joined(separator: ", ")).font(.caption)
            Button("Approve requested access", action: approve)
        }
    }
}
private struct MemberRow: View {
    let member: Member
    let canRevoke: Bool
    let revoke: () -> Void
    var body: some View {
        HStack {
            Text(member.label)
            Spacer()
            if member.revokedAt != nil { Text("Revoked").foregroundStyle(.secondary) }
            if canRevoke { Button("Revoke", role: .destructive, action: revoke) }
        }
    }
}
private struct LedgerRow: View {
    let entry: LedgerEntry
    var body: some View { VStack(alignment: .leading) { Text(entry.text); Text(entry.actorLabel).font(.caption).foregroundStyle(.secondary) } }
}
