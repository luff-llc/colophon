import ColophonSession
import SwiftUI

/// Instantiates product content only while the session is ready. Share the same source and host
/// actions with settings. Session replacement should also replace this view's identity.
public struct LibraryGate<Artwork: View, Content: View>: View {
    private let session: any LibrarySessionSource
    private let presentation: LibraryPresentation
    private let host: LibraryHostActions
    private let migrationProgress: Double?
    private let backgroundLock: BackgroundLock
    private let artwork: () -> Artwork
    private let content: () -> Content
    @State private var action = LibraryActionModel()
    @State private var joining = false
    @State private var recovering = false
    @State private var support = false
    @Environment(\.scenePhase) private var scenePhase

    /// `backgroundLock` is when the gate locks the session after the scene goes inactive or to the background: at once
    /// by default, after a delay, or `.never`. Returning to the foreground unlocks it (silent for a Secure Enclave key).
    public init(session: any LibrarySessionSource, presentation: LibraryPresentation,
                host: LibraryHostActions = .init(), migrationProgress: Double? = nil, backgroundLock: BackgroundLock = .immediately,
                @ViewBuilder artwork: @escaping () -> Artwork,
                @ViewBuilder content: @escaping () -> Content) {
        self.session = session; self.presentation = presentation; self.host = host
        self.migrationProgress = migrationProgress; self.backgroundLock = backgroundLock; self.artwork = artwork; self.content = content
    }
    private var capabilities: GateCapabilities { GateCapabilities(rejoin: host.rejoinKeys != nil, recovery: host.importRecoveryKit != nil) }
    public var body: some View {
        Group {
            switch GateModel.content(phase: session.phase, usable: session.hasUsableContent, presentation: presentation,
                                     capabilities: capabilities, migrationProgress: migrationProgress) {
            case .content(let status, let controls):
                VStack(spacing: 0) {
                    NoticesView(session: session, host: host)
                    if let status {
                        HStack {
                            Text(status)
                            ForEach(controls) { control in GateControlButton(control: control, disabled: action.isWorking, perform: perform) }
                        }.font(.caption).padding(8).accessibilityElement(children: .contain).accessibilityIdentifier("library.status")
                    }
                    content()
                }
            case .screen(let screen):
                VStack {
                    GateScreenView(screen: screen, artwork: artwork, disabled: action.isWorking, perform: perform)
                    LibraryErrorView(message: action.error).padding(.horizontal)
                }
            }
        }
        .task { await session.restore() }
        .task(id: scenePhase) {
            let scene: GateScene = switch scenePhase { case .active: .active; case .background: .background; default: .inactive }
            switch GateModel.sceneStep(scene, phase: session.phase, policy: backgroundLock) {
            case .lock(let delay):
                if delay > .zero { try? await Task.sleep(for: delay) }
                guard !Task.isCancelled else { return }
                await session.lock()
            case .unlock: await session.unlock()
            case .refresh: await session.refresh()
            case .nothing: break
            }
        }
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
    private func perform(_ gateAction: GateAction) {
        Task {
            await GateModel.perform(gateAction, session: session, host: host, model: action) { sheet in
                switch sheet {
                case .join: joining = true
                case .useRecoveryKit: recovering = true
                case .supportReport: support = true
                default: break
                }
            }
        }
    }
}

/// A full-screen gate state, rendered from its value.
struct GateScreenView<Artwork: View>: View {
    let screen: GateScreen
    let artwork: () -> Artwork
    let disabled: Bool
    let perform: (GateAction) -> Void
    var body: some View {
        LibraryStatusView(title: screen.title, message: screen.message, artwork: artwork) {
            if let code = screen.pairingCode { PairingCodeView(code: code) }
            switch screen.progress {
            case .indeterminate(let label): ProgressView(label).accessibilityIdentifier(screen.identifier + ".progress")
            case .fraction(let label, let value): ProgressView(label, value: value).accessibilityIdentifier(screen.identifier + ".progress")
            case nil: EmptyView()
            }
            ForEach(screen.controls) { control in GateControlButton(control: control, disabled: disabled, perform: perform) }
            if let footnote = screen.footnote { Text(footnote).font(.footnote).foregroundStyle(.secondary) }
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier(screen.identifier)
    }
}

/// One control, rendered from its value: its title is its label, its identifier is its accessibility identifier.
struct GateControlButton: View {
    let control: GateControl
    let disabled: Bool
    let perform: (GateAction) -> Void
    var body: some View {
        switch control.weight {
        case .prominent:
            Button(control.title) { perform(control.action) }.buttonStyle(.borderedProminent).buttonBorderShape(.capsule)
                .disabled(disabled).accessibilityIdentifier(control.identifier)
        case .destructive:
            Button(control.title, role: .destructive) { perform(control.action) }.disabled(disabled).accessibilityIdentifier(control.identifier)
        case .cancel:
            Button(control.title, role: .cancel) { perform(control.action) }.disabled(disabled).accessibilityIdentifier(control.identifier)
        case .normal:
            Button(control.title) { perform(control.action) }.disabled(disabled).accessibilityIdentifier(control.identifier)
        }
    }
}

extension LibraryGate where Artwork == Image {
    public init(session: any LibrarySessionSource, presentation: LibraryPresentation,
                host: LibraryHostActions = .init(), migrationProgress: Double? = nil, backgroundLock: BackgroundLock = .immediately,
                @ViewBuilder content: @escaping () -> Content) {
        self.init(session: session, presentation: presentation, host: host, migrationProgress: migrationProgress, backgroundLock: backgroundLock,
                  artwork: { Image(systemName: "books.vertical.fill") }, content: content)
    }
}
