import ColophonSession
import SwiftUI

/// Instantiates product content only while the session is ready. Share the same source and host
/// actions with settings. Session replacement should also replace this view's identity.
public struct LibraryGate<Artwork: View, Content: View>: View {
    private let session: any LibrarySessionSource
    private let presentation: LibraryPresentation
    private let host: LibraryHostActions
    private let migrationProgress: Double?
    private let artwork: () -> Artwork
    private let content: () -> Content
    @State private var action = LibraryActionModel()
    @State private var joining = false
    @State private var recovering = false
    @State private var support = false
    @Environment(\.scenePhase) private var scenePhase

    public init(session: any LibrarySessionSource, presentation: LibraryPresentation,
                host: LibraryHostActions = .init(), migrationProgress: Double? = nil,
                @ViewBuilder artwork: @escaping () -> Artwork,
                @ViewBuilder content: @escaping () -> Content) {
        self.session = session; self.presentation = presentation; self.host = host
        self.migrationProgress = migrationProgress; self.artwork = artwork; self.content = content
    }
    public var body: some View {
        Group {
            if session.phase == .ready { content() }
            else {
                VStack {
                    phaseView
                    LibraryErrorView(message: action.error).padding(.horizontal)
                    Button { support = true } label: {
                        Label("Support Report", systemImage: "ladybug").frame(minHeight: 44)
                    }
                        .accessibilityIdentifier("library.bugReport")
                        .padding()
                }
            }
        }
        .task { await session.restore() }
        .task(id: scenePhase) { if scenePhase == .active { await session.refresh() } }
        .sheet(isPresented: $joining) {
            LibrarySheet(title: "Use Your Library") { ConnectLibraryView(host: host, purpose: .join) }
        }
        .sheet(isPresented: $recovering) {
            LibrarySheet(title: "Recovery Kit") { RecoveryKitView(host: host) }
        }
        .sheet(isPresented: $support) {
            LibrarySheet(title: "Support Report") { SupportReportView(session: session) }
        }
    }
    @ViewBuilder private var phaseView: some View {
        switch session.phase {
        case .ready: EmptyView()
        case .noLibrary:
            LibraryStatusView(title: presentation.welcomeTitle, message: presentation.promise, artwork: artwork) {
                Button(presentation.createTitle) { Task { await action.run { await session.create() } } }
                    .buttonStyle(.borderedProminent).buttonBorderShape(.capsule)
                    .accessibilityIdentifier("library.createLocal")
                Button(presentation.joinTitle) { joining = true }
                    .accessibilityIdentifier("library.join")
                rejoinButton
                Text(presentation.dataNote).font(.footnote).foregroundStyle(.secondary)
            }
            .disabled(action.isWorking)
        case .opening: progress(title: "Opening Your Library", id: "library.opening")
        case .creating: progress(title: "Creating Your Library", id: "library.creating")
        case .migrating:
            LibraryStatusView(title: "Your Library Is Being Upgraded", message: "Your existing library is kept while the upgrade completes.", artwork: artwork) {
                if let value = migrationProgress, value.isFinite {
                    ProgressView("Upgrading library", value: min(1, max(0, value)))
                        .accessibilityIdentifier("library.migrationProgress")
                } else {
                    ProgressView("Upgrading library").accessibilityIdentifier("library.migrationProgress")
                }
                retryButton
            }.accessibilityIdentifier("library.migrating")
        case .waitingForApproval(let code):
            LibraryStatusView(title: "Waiting for Approval", message: "On a device with access, open Library settings. Approve \(presentation.appName) only when both devices show the same code.", artwork: artwork) {
                PairingCodeView(code: code)
                Button("Check Again") { Task { await action.run { await session.refresh() } } }
                    .accessibilityIdentifier("library.retryPairing")
                recoveryButton
                Button("Cancel Pairing", role: .cancel) { Task { await action.run { try await session.leave() } } }
                    .accessibilityIdentifier("library.cancelPairing")
            }.disabled(action.isWorking)
        case .denied:
            LibraryStatusView(title: "Access Has Ended", message: "This identity may have been revoked, expired, or not granted the access this app needs. Your past contributions stay attributed to you.", artwork: artwork) {
                rejoinButton
                recoveryButton
                retryButton
            }.accessibilityIdentifier("library.denied")
        case .unavailable(let reason): failure(title: "Library Unavailable", reason: reason, id: "library.unavailable")
        case .failed(let error): failure(title: "Couldn’t Open Your Library", reason: error.message, id: "library.failed")
        }
    }
    private func progress(title: String, id: String) -> some View {
        LibraryStatusView(title: title, message: "", artwork: artwork) {
            ProgressView(title).accessibilityIdentifier(id)
        }
    }
    private func failure(title: String, reason: String, id: String) -> some View {
        LibraryStatusView(title: title, message: reason, artwork: artwork) {
            retryButton
            recoveryButton
        }.accessibilityIdentifier(id)
    }
    private var retryButton: some View {
        Button("Retry") { Task { await action.run { await session.retry() } } }
            .disabled(action.isWorking).accessibilityIdentifier("library.retry")
    }
    @ViewBuilder private var rejoinButton: some View {
        if host.rejoinKeys != nil {
            Button("Rejoin Library") { Task { await action.rejoin(session: session, host: host) } }
                .accessibilityIdentifier("library.rejoin").disabled(action.isWorking)
        }
    }
    @ViewBuilder private var recoveryButton: some View {
        if host.importRecoveryKit != nil {
            Button("Use Recovery Kit") { recovering = true }.accessibilityIdentifier("library.recoverFromPairing")
        }
    }
}

extension LibraryGate where Artwork == Image {
    public init(session: any LibrarySessionSource, presentation: LibraryPresentation,
                host: LibraryHostActions = .init(), migrationProgress: Double? = nil,
                @ViewBuilder content: @escaping () -> Content) {
        self.init(session: session, presentation: presentation, host: host, migrationProgress: migrationProgress,
                  artwork: { Image(systemName: "books.vertical.fill") }, content: content)
    }
}
