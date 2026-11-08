import AuthenticationServices
import Foundation
#if os(macOS)
import AppKit
#else
import UIKit
#endif

/// One mounted view's window. A ceremony keeps the originating window and library across
/// every assertion, including the assertion after a device-presence prompt.
@MainActor public final class WebAuthnPresentationContext: NSObject {
  @TaskLocal static var current: Scope?

  @MainActor fileprivate final class Lifetime {
    var isCurrent = true
  }

  @MainActor struct Scope {
    fileprivate let context: WebAuthnPresentationContext
    fileprivate weak var window: ASPresentationAnchor?
    fileprivate let generation: UUID
    fileprivate let isCurrent: @MainActor @Sendable () -> Bool
    fileprivate let lifetime = Lifetime()

    func checkCurrent() throws {
      try Task.checkCancellation()
      guard lifetime.isCurrent, isCurrent(), context.isPresented, context.generation == generation,
        let window, context.window === window else { throw CancellationError() }
    }

    func capturedWindow() throws -> ASPresentationAnchor {
      try checkCurrent()
      guard let window else { throw CancellationError() }
      return window
    }

    func enqueuePresentation(_ start: @escaping @MainActor () -> Void,
      onFailure: @escaping @MainActor (Error) -> Void) -> UUID
    {
      let id = UUID()
      context.pendingPresentations[id] = (self, start, onFailure)
      // Register before checking. Readiness and start happen in one MainActor turn;
      // resuming an anchor continuation would introduce another inactive-scene race.
      context.update()
      return id
    }

    func removePendingPresentation(_ id: UUID) { context.pendingPresentations[id] = nil }

    func observeInvalidation(_ cancel: @escaping @MainActor () -> Void) -> UUID {
      let id = UUID()
      context.invalidationHandlers[id] = (self, cancel)
      context.update()
      return id
    }

    func removeInvalidationObserver(_ id: UUID) { context.invalidationHandlers[id] = nil }

    func finish() {
      lifetime.isCurrent = false
      context.update()
    }
  }

  private let readinessOverride: (@MainActor (ASPresentationAnchor) throws -> Bool)?
  private weak var window: ASPresentationAnchor?
  private var generation = UUID()
  private var isPresented = false
  private var pendingPresentations: [UUID: (Scope, @MainActor () -> Void, @MainActor (Error) -> Void)] = [:]
  private var invalidationHandlers: [UUID: (Scope, @MainActor () -> Void)] = [:]

  /// Creates a context for one visible host view and its originating window.
  public override convenience init() { self.init(readinessOverride: nil) }

  /// Internal deterministic readiness seam. Scope/window/session validation is never overridden.
  init(readinessOverride: (@MainActor (ASPresentationAnchor) throws -> Bool)?) {
    self.readinessOverride = readinessOverride
    super.init()
    #if os(macOS)
    let names: [Notification.Name] = [NSApplication.didBecomeActiveNotification, NSApplication.didHideNotification,
      NSWindow.didBecomeKeyNotification, NSWindow.willCloseNotification, NSWindow.didMiniaturizeNotification]
    #else
    let names: [Notification.Name] = [UIScene.didActivateNotification, UIScene.didEnterBackgroundNotification,
      UIScene.didDisconnectNotification, UIWindow.didBecomeVisibleNotification, UIWindow.didBecomeHiddenNotification]
    #endif
    for name in names {
      NotificationCenter.default.addObserver(self, selector: #selector(lifecycleChanged(_:)), name: name, object: nil)
    }
  }

  deinit { NotificationCenter.default.removeObserver(self) }

  /// Binds this context to an AppKit or UIKit host window.
  public func mount(_ window: ASPresentationAnchor?) {
    if self.window !== window { generation = UUID() }
    self.window = window
    update()
  }

  /// Marks the host as presented.
  public func appear() { isPresented = true }

  /// Cancels actions when the host disappears.
  public func disappear() {
    isPresented = false
    invalidate()
  }

  /// Cancels actions when the selected host session changes.
  public func invalidate() {
    generation = UUID()
    update()
  }

  func unmount(_ window: ASPresentationAnchor?) {
    guard self.window === window else { return }
    mount(nil)
  }

  /// Runs a complete key action in this host's mounted window for the selected session.
  ///
  /// Mount this context with `View.webAuthnPresentation(_:identity:)` before starting the action.
  /// Keep all prompts for one action inside `operation`; the window and session stay bound
  /// across suspension. Cancellation, disappearance or replacement invalidates the action.
  /// - Returns: The operation's result while the originating presentation is still current.
  /// - Throws: The operation's error, a missing-window error, or `CancellationError`.
  public func perform<T: Sendable>(isCurrent: @escaping @MainActor @Sendable () -> Bool = { true },
    operation: @escaping @MainActor () async throws -> T) async throws -> T
  {
    guard isPresented else { throw CancellationError() }
    guard let window else {
      throw KeyProviderError.unsupportedHere
    }
    let scope = Scope(context: self, window: window, generation: generation, isCurrent: isCurrent)
    // The native lifecycle can cancel between ceremonies too, while a presence prompt is
    // open. Keep that bridge's task handle, propagate caller cancellation, and remove it on exit.
    let task = Task { @MainActor in
      try await Self.$current.withValue(scope) {
        try scope.checkCurrent()
        let result = try await operation()
        try scope.checkCurrent()
        return result
      }
    }
    let observer = scope.observeInvalidation { task.cancel() }
    defer {
      scope.removeInvalidationObserver(observer)
      scope.finish()
    }
    let result = try await withTaskCancellationHandler {
      try await task.value
    } onCancel: {
      task.cancel()
    }
    // The child can finish before this parent resumes; do not return success into a
    // dismissed/replaced window or session in that final scheduling gap.
    try scope.checkCurrent()
    return result
  }

  /// A temporarily inactive scene is normal after AuthenticationServices or Face ID.
  /// A background, disconnected, replaced or unmounted window must never receive the next prompt.
  private func ready(_ scope: Scope) throws -> Bool {
    try scope.checkCurrent()
    guard let window = scope.window else { throw CancellationError() }
    if let readinessOverride { return try readinessOverride(window) }
    #if os(macOS)
    guard !NSApp.isHidden, window.isVisible, !window.isMiniaturized else { throw CancellationError() }
    return NSApp.isActive
    #else
    guard !window.isHidden, let scene = window.windowScene else { throw CancellationError() }
    switch scene.activationState {
    case .foregroundActive: return true
    case .foregroundInactive: return false
    case .background, .unattached: throw CancellationError()
    @unknown default: throw CancellationError()
    }
    #endif
  }

  @objc private func lifecycleChanged(_ notification: Notification) {
    #if os(macOS)
    if notification.name == NSApplication.didHideNotification {
      invalidate()
      return
    }
    if (notification.name == NSWindow.willCloseNotification || notification.name == NSWindow.didMiniaturizeNotification),
      let changed = notification.object as? NSWindow, changed === window {
      invalidate()
      return
    }
    #else
    if (notification.name == UIScene.didEnterBackgroundNotification || notification.name == UIScene.didDisconnectNotification),
      let scene = notification.object as? UIWindowScene, scene === window?.windowScene {
      invalidate()
      return
    }
    #endif
    update()
  }

  private func update() {
    for (id, (scope, start, onFailure)) in Array(pendingPresentations) {
      guard pendingPresentations[id] != nil else { continue }
      do {
        if try ready(scope), pendingPresentations.removeValue(forKey: id) != nil {
          start()
        }
      } catch {
        if pendingPresentations.removeValue(forKey: id) != nil { onFailure(error) }
      }
    }
    for (id, (scope, cancel)) in Array(invalidationHandlers) {
      guard invalidationHandlers[id] != nil else { continue }
      do { _ = try ready(scope) }
      catch {
        if invalidationHandlers.removeValue(forKey: id) != nil { cancel() }
      }
    }
  }

}
