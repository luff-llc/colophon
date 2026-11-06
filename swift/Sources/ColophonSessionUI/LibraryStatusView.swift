import SwiftUI

struct LibraryStatusView<Artwork: View, Actions: View>: View {
    let title: String
    let message: String
    @ViewBuilder let artwork: () -> Artwork
    @ViewBuilder let actions: () -> Actions
    @Environment(\.dynamicTypeSize) private var typeSize
    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                if !typeSize.isAccessibilitySize { artwork().font(.largeTitle).accessibilityHidden(true) }
                Text(title).font(.largeTitle.bold()).accessibilityAddTraits(.isHeader)
                Text(message).font(.title3).foregroundStyle(.secondary)
                actions().buttonStyle(.bordered).controlSize(.large)
            }
            .multilineTextAlignment(.center)
            .padding(32)
            .frame(maxWidth: 560)
            .frame(maxWidth: .infinity)
        }
        .scrollBounceBehavior(.basedOnSize)
    }
}

struct LibraryErrorView: View {
    let message: String?
    var body: some View {
        if let message {
            Label(message, systemImage: "exclamationmark.triangle")
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("library.actionError")
        }
    }
}
