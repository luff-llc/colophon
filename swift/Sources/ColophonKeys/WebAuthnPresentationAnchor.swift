import SwiftUI
#if os(macOS)
import AppKit
#else
import UIKit
#endif

/// Reads only the native window containing the action's own view; never searches the app's scenes.
@MainActor struct WebAuthnPresentationAnchor {
  let presentation: WebAuthnPresentationContext

  #if os(macOS)
  final class Probe: NSView {
    override func hitTest(_ point: NSPoint) -> NSView? { nil }
    var presentation: WebAuthnPresentationContext?
    override func viewDidMoveToWindow() {
      super.viewDidMoveToWindow()
      presentation?.mount(window)
    }
  }
  #else
  final class Probe: UIView {
    var presentation: WebAuthnPresentationContext?
    override func didMoveToWindow() {
      super.didMoveToWindow()
      presentation?.mount(window)
    }
  }
  #endif
}

#if os(macOS)
extension WebAuthnPresentationAnchor: NSViewRepresentable {
  func makeNSView(context: Context) -> Probe {
    let view = Probe()
    view.presentation = presentation
    return view
  }
  func updateNSView(_ view: Probe, context: Context) { presentation.mount(view.window) }
  static func dismantleNSView(_ view: Probe, coordinator: ()) { view.presentation?.unmount(view.window) }
}
#else
extension WebAuthnPresentationAnchor: UIViewRepresentable {
  func makeUIView(context: Context) -> Probe {
    let view = Probe()
    view.isUserInteractionEnabled = false
    view.presentation = presentation
    return view
  }
  func updateUIView(_ view: Probe, context: Context) { presentation.mount(view.window) }
  static func dismantleUIView(_ view: Probe, coordinator: ()) { view.presentation?.unmount(view.window) }
}
#endif
