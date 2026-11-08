import SwiftUI

@MainActor public extension View {
  /// Mounts the originating window for a complete key action. Changing the host's session identity cancels it.
  /// Keep the context in host state; run prompts inside `WebAuthnPresentationContext.perform`.
  func webAuthnPresentation<ID: Equatable>(_ context: WebAuthnPresentationContext, identity: ID) -> some View {
    background(WebAuthnPresentationAnchor(presentation: context))
      .onAppear { context.appear() }
      .onDisappear { context.disappear() }
      .onChange(of: identity) { _, _ in context.invalidate() }
  }
}
