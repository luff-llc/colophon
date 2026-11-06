import SwiftUI
import ColophonSession
import ColophonSessionUI

struct SampleView: View {
    let session: ColophonSession
    let host: LibraryHostActions
    @State private var links: NamespaceStore<SavedLinksQuery, [SavedLink]>
    @State private var address = "https://example.com"
    @State private var title = "Example"
    @State private var error: String?
    private let query = SavedLinksQuery()
    init(session: ColophonSession, host: LibraryHostActions) {
        self.session = session
        self.host = host
        _links = State(initialValue: NamespaceStore(savedLinksIn: session))
    }
    var body: some View {
        LibraryGate(session: session,
                    presentation: .init(appName: "Colophon", promise: "Keep what matters in a library you own."),
                    host: host) {
            Image(systemName: "books.vertical.fill").font(.largeTitle).foregroundStyle(.tint)
        } content: {
            NavigationStack {
                libraryView
                    .navigationTitle("Colophon")
                    .task(id: session.namespaceRevisions["reading.saved"]) { await warmLinks() }
                    .toolbar {
                        NavigationLink {
                            LibrarySettingsView(session: session, host: host)
                        } label: { Label("Library Settings", systemImage: "gearshape") }
                        .accessibilityIdentifier("sample.librarySettings")
                    }
                    .alert("Couldn’t finish", isPresented: Binding(get: { error != nil }, set: { if !$0 { error = nil } })) {
                        Button("OK") { error = nil }
                    } message: { Text(error ?? "") }
            }
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
