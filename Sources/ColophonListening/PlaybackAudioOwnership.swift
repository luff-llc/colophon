import Foundation

/// Process-local arbitration for Taupe's single audio session. A capture reserves the
/// session before requesting microphone permission, so a remote Play cannot take it.
/// Tokens prevent an old recorder callback from releasing a newer playback session.
@MainActor public final class PlaybackAudioOwnership {
  public enum Kind: Sendable, Equatable { case playback, capture }

  public struct Lease: Sendable, Equatable {
    public let id: UUID
    public let kind: Kind
    fileprivate init(kind: Kind) {
      id = UUID()
      self.kind = kind
    }
  }

  public static let shared = PlaybackAudioOwnership()

  private var current: Lease?
  private var activatedCapture = false
  private var epoch: UInt64 = 0
  /// Physical transitions survive logical revocation until their cleanup has completed.
  @MainActor private final class Transition {
    let lease: Lease
    var completed = false
    var failure: (any Error)?
    init(lease: Lease) { self.lease = lease }
  }
  private var transition: Transition?
  private var transitionWaiters: [CheckedContinuation<Void, Never>] = []
  private var pendingPlaybackRequestID: UUID?
  private var unclaimedPlayback: (lease: Lease, requestID: UUID)?
  public private(set) var lastCleanupFailure: String?
  public private(set) var interruptionActive = false

  public var captureReserved: Bool { current?.kind == .capture }

  public init() {}

  /// The caller must pause playback before reserving the microphone.
  public func reserveCapture() -> Lease? {
    guard !interruptionActive, current == nil else { return nil }
    let lease = Lease(kind: .capture)
    current = lease
    return lease
  }

  /// Activation failures do not grant ownership. The caller cleans up any partial
  /// platform category change in its catch block while its lease is still current.
  public func activateCapture(_ lease: Lease, activate: () throws -> Void) throws -> Bool {
    guard transition == nil, !interruptionActive, current == lease, lease.kind == .capture else { return false }
    if activatedCapture { return true }
    let startingEpoch = epoch
    try activate()
    guard epoch == startingEpoch, !interruptionActive, current == lease else { return false }
    activatedCapture = true
    return true
  }

  /// Returns nil while capture permission or recording owns the session. A throwing
  /// platform activation leaves the previous ownership unchanged.
  public func acquirePlayback(requestID: UUID? = nil, recoveringInterruption: Bool = false,
    activate: () throws -> Void) throws -> Lease?
  {
    guard transition == nil, !interruptionActive || recoveringInterruption else { return nil }
    if current?.kind == .capture { return nil }
    if let current {
      if let requestID, unclaimedPlayback?.lease == current {
        unclaimedPlayback = (current, requestID)
        pendingPlaybackRequestID = requestID
      }
      return current
    }
    let startingEpoch = epoch
    try activate()
    guard epoch == startingEpoch, !interruptionActive || recoveringInterruption, current == nil else { return nil }
    if recoveringInterruption { interruptionActive = false }
    let lease = Lease(kind: .playback)
    current = lease
    if let requestID {
      unclaimedPlayback = (lease, requestID)
      pendingPlaybackRequestID = requestID
    }
    return lease
  }

  @discardableResult public func release(_ lease: Lease, deactivate: () -> Void = {}) -> Bool {
    guard current == lease else { return false }
    if unclaimedPlayback?.lease == lease { unclaimedPlayback = nil }
    if lease.kind == .playback { pendingPlaybackRequestID = nil }
    if transition?.lease == lease {
      // The in-flight operation owns cleanup, so no later callback may grant this lease.
      epoch &+= 1
      current = nil
      activatedCapture = false
      return true
    }
    let mustDeactivate = lease.kind == .capture && activatedCapture
    current = nil
    activatedCapture = false
    if mustDeactivate { deactivate() }
    return true
  }

  /// Only a matching pending request can revoke provisional playback. A returned lease is
  /// explicitly claimed by its caller before I/O; another existing owner is never discarded.
  public func cancelPlaybackActivation(requestID: UUID) {
    guard pendingPlaybackRequestID == requestID || unclaimedPlayback?.requestID == requestID,
      current?.kind == .playback else { return }
    epoch &+= 1
    current = nil
    if pendingPlaybackRequestID == requestID { pendingPlaybackRequestID = nil }
    if unclaimedPlayback?.requestID == requestID { unclaimedPlayback = nil }
  }

  public func isUnclaimedPlayback(_ lease: Lease, requestID: UUID) -> Bool {
    unclaimedPlayback?.lease == lease && unclaimedPlayback?.requestID == requestID
  }

  public func claimPlayback(_ lease: Lease, requestID: UUID) -> Bool {
    guard transition == nil, !interruptionActive, current == lease, lease.kind == .playback else { return false }
    if unclaimedPlayback?.lease == lease {
      guard unclaimedPlayback?.requestID == requestID else { return false }
      unclaimedPlayback = nil
      pendingPlaybackRequestID = nil
    }
    return true
  }

  @discardableResult public func discardUnclaimedPlayback(_ lease: Lease, requestID: UUID) -> Bool {
    guard unclaimedPlayback?.lease == lease, unclaimedPlayback?.requestID == requestID else { return false }
    unclaimedPlayback = nil
    if pendingPlaybackRequestID == requestID { pendingPlaybackRequestID = nil }
    return release(lease)
  }

  public func acquirePlayback(requestID: UUID, recoveringInterruption: Bool = false,
    activate: @MainActor () async throws -> Void,
    deactivate: @escaping @MainActor () async throws -> Void,
    isValid: @MainActor () -> Bool = { true }) async throws -> Lease?
  {
    let requestEpoch = epoch
    try await waitForTransition()
    guard !Task.isCancelled, isValid(), epoch == requestEpoch,
      !interruptionActive || recoveringInterruption,
      current?.kind != .capture else { return nil }
    if let current {
      if unclaimedPlayback?.lease == current {
        unclaimedPlayback = (current, requestID)
        pendingPlaybackRequestID = requestID
      }
      return current
    }
    let lease = Lease(kind: .playback)
    current = lease
    pendingPlaybackRequestID = requestID
    let startingEpoch = epoch
    let operation = Transition(lease: lease)
    transition = operation
    var activationFailure: (any Error)?
    do { try await activate() } catch { activationFailure = error }
    if activationFailure == nil, !Task.isCancelled, isValid(), epoch == startingEpoch,
      !interruptionActive || recoveringInterruption, current == lease
    {
      if recoveringInterruption { interruptionActive = false }
      unclaimedPlayback = (lease, requestID)
      finishTransition(operation)
      return lease
    }
    do { try await cleanupTransition(operation, deactivate: deactivate) }
    catch {
      if current == lease { current = nil }
      if pendingPlaybackRequestID == requestID { pendingPlaybackRequestID = nil }
      throw error
    }
    if current == lease { current = nil }
    if pendingPlaybackRequestID == requestID { pendingPlaybackRequestID = nil }
    if let activationFailure { throw activationFailure }
    return nil
  }

  public func activateCapture(_ lease: Lease,
    activate: @MainActor () async throws -> Void,
    deactivate: @escaping @MainActor () async throws -> Void,
    isValid: @MainActor () -> Bool = { true }) async throws -> Bool
  {
    try await waitForTransition()
    guard !Task.isCancelled, isValid(), !interruptionActive,
      current == lease, lease.kind == .capture else { return false }
    if activatedCapture { return true }
    let startingEpoch = epoch
    let operation = Transition(lease: lease)
    transition = operation
    var activationFailure: (any Error)?
    do { try await activate() } catch { activationFailure = error }
    if activationFailure == nil, !Task.isCancelled, isValid(), epoch == startingEpoch,
      !interruptionActive, current == lease
    {
      activatedCapture = true
      finishTransition(operation)
      return true
    }
    do { try await cleanupTransition(operation, deactivate: deactivate) }
    catch {
      if current == lease { current = nil; activatedCapture = false }
      throw error
    }
    if current == lease { current = nil; activatedCapture = false }
    if let activationFailure { throw activationFailure }
    return false
  }

  /// Permission and unfinished activation own no recording I/O. Revoke immediately; an
  /// in-flight physical activation, if any, retains its own cleanup barrier.
  @discardableResult public func releasePendingCapture(_ lease: Lease) -> Bool {
    guard current == lease, lease.kind == .capture, !activatedCapture else { return false }
    return release(lease)
  }

  /// Stop I/O first. Establish the cleanup barrier synchronously, before Stop returns.
  /// A subsequent explicit Play may wait, but cannot activate before deactivation completes.
  @discardableResult public func beginCaptureRelease(_ lease: Lease,
    deactivate: @escaping @MainActor () async throws -> Void) -> Bool
  {
    guard current == lease, lease.kind == .capture else { return false }
    if releasePendingCapture(lease) { return true }
    guard transition == nil else { return false }
    let operation = Transition(lease: lease)
    transition = operation
    current = nil
    activatedCapture = false
    epoch &+= 1
    Task {
      do { try await deactivate(); finishTransition(operation) }
      catch { failTransition(operation, error: error) }
    }
    return true
  }

  /// Wait for this released lease only, never an unrelated later playback transition.
  public func waitForCaptureRelease(_ lease: Lease) async -> Bool {
    guard let operation = transition, operation.lease == lease else { return true }
    while !operation.completed {
      await withCheckedContinuation { transitionWaiters.append($0) }
    }
    return operation.failure == nil
  }

  @discardableResult public func releaseCapture(_ lease: Lease,
    deactivate: @escaping @MainActor () async throws -> Void) async -> Bool
  {
    guard beginCaptureRelease(lease, deactivate: deactivate) else { return false }
    return await waitForCaptureRelease(lease)
  }

  private func waitForTransition() async throws {
    while transition != nil {
      await withCheckedContinuation { transitionWaiters.append($0) }
    }
  }

  private func cleanupTransition(_ operation: Transition,
    deactivate: @escaping @MainActor () async throws -> Void) async throws
  {
    // Unstructured cleanup deliberately does not inherit the cancelled request's status.
    // The physical barrier is retained until the actual native result has been checked.
    let cleanup = Task { try await deactivate() }
    do { try await cleanup.value; finishTransition(operation) }
    catch { failTransition(operation, error: error); throw error }
  }

  private func resumeTransitionWaiters() {
    let waiters = transitionWaiters
    transitionWaiters.removeAll()
    for waiter in waiters { waiter.resume() }
  }

  private func finishTransition(_ operation: Transition) {
    guard transition === operation else { return }
    operation.completed = true
    transition = nil
    resumeTransitionWaiters()
  }

  private func failTransition(_ operation: Transition, error: any Error) {
    guard transition === operation else { return }
    operation.failure = error
    lastCleanupFailure = error.localizedDescription
    // The callback completed, so no old physical mutation remains in flight. I/O was already
    // stopped or never started; a fresh explicit activation may retry its full configuration.
    finishTransition(operation)
  }

  public func isCurrent(_ lease: Lease) -> Bool { current == lease }

  /// Interruption or lost output route revokes all leases. A stale cleanup cannot
  /// deactivate a session acquired after this point.
  public func invalidate() {
    epoch &+= 1
    current = nil
    activatedCapture = false
    unclaimedPlayback = nil
    pendingPlaybackRequestID = nil
  }

  /// Automatic requests wait for the end notification. A deliberate Play may ask the
  /// platform to reactivate; only a successful activation in this epoch clears the block.
  public func beginInterruption() {
    invalidate()
    interruptionActive = true
  }

  public func endInterruption() {
    interruptionActive = false
  }
}
