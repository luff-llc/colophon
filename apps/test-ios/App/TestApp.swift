import ColophonKeys
import ColophonSession
import SwiftUI

@main struct ColophonTestApp: App {
    @State private var model = AppModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(model)
                .webAuthnPresentation(model.presentation, identity: model.settings.slot ?? "")
                .onOpenURL { url in Task { await model.open(url) } }
                .onChange(of: scenePhase) { _, phase in
                    // Lock in the background (no secret held while away), unlock on return.
                    switch phase {
                    case .background: if model.session?.phase == .ready { Task { await model.lock() } }
                    case .active: if model.session?.phase == .locked { Task { await model.unlock() } }
                    default: break
                    }
                }
        }
    }
}

struct RootView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Group {
            if model.settings.slot == nil {
                NavigationStack { SetupView() }
            } else if let session = model.session {
                switch session.phase {
                case .waitingForApproval(let code): NavigationStack { WaitingView(code: code) }
                default: MainTabs()
                }
            } else {
                ProgressView("Opening")
            }
        }
        .overlay(alignment: .bottom) {
            if let busy = model.busy {
                Text(busy + "…").padding(8).background(.thinMaterial, in: Capsule()).padding().accessibilityIdentifier("busy")
            }
        }
        .alert("Error", isPresented: Binding(get: { model.actionError != nil }, set: { if !$0 { model.actionError = nil } })) {
            Button("OK") { model.actionError = nil }
        } message: {
            Text(model.actionError ?? "")
        }
    }
}

struct MainTabs: View {
    var body: some View {
        TabView {
            NavigationStack { NotesView() }.tabItem { Label("Notes", systemImage: "note.text") }
            NavigationStack { DevicesView() }.tabItem { Label("Devices", systemImage: "iphone.gen3") }
            NavigationStack { StatusView() }.tabItem { Label("Status", systemImage: "info.circle") }
        }
    }
}
