import ColophonListening
import Testing

@MainActor struct PlaybackAudioOwnershipTests {
  private enum ActivationFailure: Error { case rejected }

  @Test func captureReservationBlocksRemotePlaybackUntilPermissionCompletes() throws {
    let ownership = PlaybackAudioOwnership()
    let capture = try #require(ownership.reserveCapture())
    var playbackActivationCount = 0

    let blocked = try ownership.acquirePlayback { playbackActivationCount += 1 }
    #expect(blocked == nil)
    #expect(playbackActivationCount == 0)
    #expect(ownership.isCurrent(capture))

    #expect(ownership.release(capture))
    let resumed = try #require(ownership.acquirePlayback { playbackActivationCount += 1 })
    #expect(resumed.kind == .playback)
    #expect(playbackActivationCount == 1)
  }

  @Test func activationFailureRetainsOnlyPendingCaptureAndPlaybackFailureGrantsNoLease() throws {
    let ownership = PlaybackAudioOwnership()
    let capture = try #require(ownership.reserveCapture())
    #expect(throws: ActivationFailure.rejected) {
      try ownership.activateCapture(capture) { throw ActivationFailure.rejected }
    }
    #expect(ownership.isCurrent(capture))
    #expect(try ownership.acquirePlayback {} == nil)

    #expect(ownership.release(capture))
    #expect(throws: ActivationFailure.rejected) {
      try ownership.acquirePlayback { throw ActivationFailure.rejected }
    }
    let resumed = try #require(ownership.acquirePlayback {})
    #expect(resumed.kind == .playback)
    #expect(ownership.isCurrent(resumed))
  }

  @Test func staleRecorderCleanupCannotDeactivatePlaybackAfterInterruptionOrRouteLoss() throws {
    let ownership = PlaybackAudioOwnership()
    let capture = try #require(ownership.reserveCapture())
    var captureActivationCount = 0
    try #expect(ownership.activateCapture(capture) { captureActivationCount += 1 })
    #expect(captureActivationCount == 1)

    // Interruption and loss of the output route both invalidate the old lease.
    ownership.invalidate()
    let playback = try #require(ownership.acquirePlayback {})
    var deactivationCount = 0
    #expect(!ownership.release(capture) { deactivationCount += 1 })
    #expect(deactivationCount == 0)
    #expect(ownership.isCurrent(playback))

    // Resume is deliberate: only a fresh playback acquisition activates playback.
    ownership.invalidate()
    var playbackActivationCount = 0
    let resumed = try #require(ownership.acquirePlayback { playbackActivationCount += 1 })
    #expect(resumed.kind == .playback)
    #expect(playbackActivationCount == 1)
  }

  @Test func activeInterruptionBlocksNewOwnersUntilEndedWithoutAutoResume() throws {
    let ownership = PlaybackAudioOwnership()
    let playing = try #require(ownership.acquirePlayback {})
    ownership.beginInterruption()

    #expect(!ownership.isCurrent(playing))
    #expect(ownership.reserveCapture() == nil)
    #expect(try ownership.acquirePlayback {} == nil)

    ownership.endInterruption()
    var activationCount = 0
    let resumed = try #require(ownership.acquirePlayback { activationCount += 1 })
    #expect(resumed.kind == .playback)
    #expect(activationCount == 1)
  }

  @Test func synchronousRevocationDuringActivationCannotGrantStaleOwnership() throws {
    let ownership = PlaybackAudioOwnership()
    let capture = try #require(ownership.reserveCapture())
    let captureActivated = try ownership.activateCapture(capture) {
      ownership.invalidate()
    }
    #expect(!captureActivated)
    #expect(!ownership.isCurrent(capture))

    let playback = try ownership.acquirePlayback {
      ownership.beginInterruption()
      ownership.endInterruption()
    }
    #expect(playback == nil)
    #expect(!ownership.interruptionActive)
  }

  @Test func explicitRecoveryClearsInterruptionOnlyAfterNativeActivationSucceeds() throws {
    let ownership = PlaybackAudioOwnership()
    ownership.beginInterruption()
    #expect(throws: ActivationFailure.rejected) {
      try ownership.acquirePlayback(recoveringInterruption: true) { throw ActivationFailure.rejected }
    }
    #expect(ownership.interruptionActive)
    let automatic = try ownership.acquirePlayback { Issue.record("Automatic playback attempted reactivation") }
    #expect(automatic == nil)
    let recovered = try ownership.acquirePlayback(recoveringInterruption: true) {}
    let lease = try #require(recovered)
    #expect(ownership.interruptionActive == false)
    #expect(ownership.isCurrent(lease))
  }

  @Test func explicitRecoveryCannotDisplaceCapture() throws {
    let ownership = PlaybackAudioOwnership()
    let capture = try #require(ownership.reserveCapture())
    let playback = try ownership.acquirePlayback(recoveringInterruption: true) {
      Issue.record("Explicit Play activated over a capture reservation")
    }
    #expect(playback == nil)
    #expect(ownership.isCurrent(capture))
  }

  @Test func completedCaptureReleasesItsSessionExactlyOnce() throws {
    let ownership = PlaybackAudioOwnership()
    let capture = try #require(ownership.reserveCapture())
    try #expect(ownership.activateCapture(capture) {})
    var deactivationCount = 0
    #expect(ownership.release(capture) { deactivationCount += 1 })
    #expect(!ownership.release(capture) { deactivationCount += 1 })
    #expect(deactivationCount == 1)
  }
}

import Foundation

@MainActor private final class OwnershipSignal {
  private(set) var fired = false
  private var waiters: [CheckedContinuation<Void, Never>] = []

  func wait() async {
    if fired { return }
    await withCheckedContinuation { waiters.append($0) }
  }

  func fire() {
    guard !fired else { return }
    fired = true
    let pending = waiters
    waiters.removeAll()
    for waiter in pending { waiter.resume() }
  }
}

extension PlaybackAudioOwnershipTests {
  @Test func asynchronousExplicitRecoveryRejectsNativeFailureAndCaptureReservation() async throws {
    let ownership = PlaybackAudioOwnership()
    ownership.beginInterruption()
    do {
      _ = try await ownership.acquirePlayback(requestID: UUID(), recoveringInterruption: true,
        activate: { throw ActivationFailure.rejected }, deactivate: {})
      Issue.record("Native activation failure was not returned")
    } catch ActivationFailure.rejected {}
    #expect(ownership.interruptionActive)
    ownership.endInterruption()
    let capture = try #require(ownership.reserveCapture())
    let playback = try await ownership.acquirePlayback(requestID: UUID(), recoveringInterruption: true,
      activate: { Issue.record("Explicit Play activated over capture") }, deactivate: {})
    #expect(playback == nil)
    #expect(ownership.isCurrent(capture))
  }

  @Test func asynchronousExplicitRecoveryClearsLatchOnlyAfterActivation() async throws {
    let ownership = PlaybackAudioOwnership()
    ownership.beginInterruption()
    let entered = OwnershipSignal()
    let finish = OwnershipSignal()
    let request = Task { @MainActor in
      try await ownership.acquirePlayback(requestID: UUID(), recoveringInterruption: true, activate: {
        entered.fire()
        await finish.wait()
      }, deactivate: {})
    }
    await entered.wait()
    #expect(ownership.interruptionActive)
    finish.fire()
    let result = try await request.value
    let lease = try #require(result)
    #expect(ownership.interruptionActive == false)
    #expect(ownership.isCurrent(lease))
  }

  @Test(arguments: [false, true])
  func newerInterruptionRevokesHeldExplicitRecovery(endsBeforeActivationFinishes: Bool) async throws {
    let ownership = PlaybackAudioOwnership()
    ownership.beginInterruption()
    let entered = OwnershipSignal()
    let finish = OwnershipSignal()
    let cleanup = OwnershipSignal()
    let request = Task { @MainActor in
      try await ownership.acquirePlayback(requestID: UUID(), recoveringInterruption: true, activate: {
        entered.fire()
        await finish.wait()
      }, deactivate: { cleanup.fire() })
    }
    await entered.wait()
    ownership.beginInterruption()
    if endsBeforeActivationFinishes { ownership.endInterruption() }
    finish.fire()
    let result = try await request.value
    #expect(result == nil)
    #expect(cleanup.fired)
    #expect(ownership.interruptionActive == !endsBeforeActivationFinishes)
  }

  @Test(arguments: [false, true])
  func newerInterruptionRevokesExplicitRecoveryWaitingForCleanup(endsBeforeCleanupFinishes: Bool) async throws {
    let ownership = PlaybackAudioOwnership()
    let oldActivationEntered = OwnershipSignal()
    let finishOldActivation = OwnershipSignal()
    let cleanupEntered = OwnershipSignal()
    let finishCleanup = OwnershipSignal()
    let oldRequest = Task { @MainActor in
      try await ownership.acquirePlayback(requestID: UUID(), activate: {
        oldActivationEntered.fire()
        await finishOldActivation.wait()
      }, deactivate: {
        cleanupEntered.fire()
        await finishCleanup.wait()
      })
    }
    await oldActivationEntered.wait()
    ownership.beginInterruption()
    finishOldActivation.fire()
    await cleanupEntered.wait()

    let recoveryStarted = OwnershipSignal()
    let recovery = Task { @MainActor in
      recoveryStarted.fire()
      return try await ownership.acquirePlayback(requestID: UUID(), recoveringInterruption: true,
        activate: { Issue.record("Stale explicit Play activated after a newer interruption") },
        deactivate: {})
    }
    // The recovery task reaches waitForTransition before this actor resumes.
    await recoveryStarted.wait()
    ownership.beginInterruption()
    if endsBeforeCleanupFinishes { ownership.endInterruption() }
    finishCleanup.fire()

    let oldResult = try await oldRequest.value
    let recoveryResult = try await recovery.value
    #expect(oldResult == nil)
    #expect(recoveryResult == nil)
    #expect(ownership.interruptionActive == !endsBeforeCleanupFinishes)
  }

  @Test func pendingPlaybackActivationReservesBeforeNativeAudioStarts() async throws {
    let ownership = PlaybackAudioOwnership()
    let entered = OwnershipSignal()
    let finishActivation = OwnershipSignal()
    let requestID = UUID()
    var activationCount = 0
    let request = Task { @MainActor in
      try await ownership.acquirePlayback(requestID: requestID, activate: {
        activationCount += 1
        entered.fire()
        await finishActivation.wait()
      }, deactivate: {})
    }

    await entered.wait()
    #expect(activationCount == 1)
    #expect(ownership.reserveCapture() == nil)
    let competingRemote = try ownership.acquirePlayback { activationCount += 1 }
    #expect(competingRemote == nil)
    #expect(activationCount == 1)

    finishActivation.fire()
    let playbackResult = try await request.value
    let playback = try #require(playbackResult)
    #expect(ownership.isCurrent(playback))
  }

  @Test func cancelledPlaybackActivationKeepsCleanupBarrierBeforeCaptureStarts() async throws {
    let ownership = PlaybackAudioOwnership()
    let entered = OwnershipSignal()
    let finishActivation = OwnershipSignal()
    let cleanupEntered = OwnershipSignal()
    let finishCleanup = OwnershipSignal()
    let captureStarted = OwnershipSignal()
    let requestID = UUID()
    var cleanupRanInCancelledTask = true
    let playback = Task { @MainActor in
      try await ownership.acquirePlayback(requestID: requestID, activate: {
        entered.fire()
        await finishActivation.wait()
      }, deactivate: {
        cleanupRanInCancelledTask = Task.isCancelled
        cleanupEntered.fire()
        await finishCleanup.wait()
      })
    }

    await entered.wait()
    playback.cancel()
    ownership.cancelPlaybackActivation(requestID: requestID)
    let capture = try #require(ownership.reserveCapture())
    let recording = Task { @MainActor in
      try await ownership.activateCapture(capture, activate: {
        captureStarted.fire()
      }, deactivate: {})
    }
    finishActivation.fire()
    await cleanupEntered.wait()
    #expect(!captureStarted.fired, "Capture cannot change the audio category during stale playback cleanup")
    #expect(ownership.isCurrent(capture))

    finishCleanup.fire()
    let playbackResult = try await playback.value
    let recordingResult = try await recording.value
    #expect(playbackResult == nil)
    #expect(!cleanupRanInCancelledTask, "Physical cleanup must survive cancellation of the request")
    #expect(recordingResult)
    #expect(captureStarted.fired)
    #expect(ownership.isCurrent(capture))
  }

  @Test func throwingPlaybackActivationCleansPhysicalSessionBeforeNewOwner() async throws {
    let ownership = PlaybackAudioOwnership()
    let cleanupEntered = OwnershipSignal()
    let finishCleanup = OwnershipSignal()
    var cleanupCount = 0
    let request = Task { @MainActor in
      try await ownership.acquirePlayback(requestID: UUID(), activate: {
        throw ActivationFailure.rejected
      }, deactivate: {
        cleanupCount += 1
        cleanupEntered.fire()
        await finishCleanup.wait()
      })
    }

    await cleanupEntered.wait()
    #expect(ownership.reserveCapture() == nil)
    #expect(cleanupCount == 1)
    finishCleanup.fire()
    do {
      _ = try await request.value
      Issue.record("A failed native activation must not grant playback")
    } catch ActivationFailure.rejected {
      // Expected after the partial native session has been deactivated.
    }
    let capture = try #require(ownership.reserveCapture())
    #expect(ownership.isCurrent(capture))
  }

  @Test func stopCleanupWaitsForPhysicalDeactivationAndPauseCancelsLatePlay() async throws {
    let ownership = PlaybackAudioOwnership()
    let capture = try #require(ownership.reserveCapture())
    let activated = try await ownership.activateCapture(capture, activate: {}, deactivate: {})
    #expect(activated)

    let cleanupEntered = OwnershipSignal()
    let finishCleanup = OwnershipSignal()
    let didBeginRelease = ownership.beginCaptureRelease(capture, deactivate: {
      cleanupEntered.fire()
      await finishCleanup.wait()
    })
    #expect(didBeginRelease)
    #expect(!ownership.isCurrent(capture), "Stop must mark its cleanup barrier before returning")
    await cleanupEntered.wait()
    var playStillWanted = true
    var playbackActivationCount = 0
    let queuedPlay = Task { @MainActor in
      try await ownership.acquirePlayback(requestID: UUID(), activate: {
        playbackActivationCount += 1
      }, deactivate: {}, isValid: { playStillWanted })
    }

    #expect(playbackActivationCount == 0)
    playStillWanted = false // Manual Pause while Stop is still restoring the audio session.
    finishCleanup.fire()
    let queuedResult = try await queuedPlay.value
    #expect(queuedResult == nil)
    #expect(playbackActivationCount == 0)

    let freshPlayEntered = OwnershipSignal()
    let finishFreshPlay = OwnershipSignal()
    let explicitPlay = Task { @MainActor in
      try await ownership.acquirePlayback(requestID: UUID(), activate: {
        playbackActivationCount += 1
        freshPlayEntered.fire()
        await finishFreshPlay.wait()
      }, deactivate: {})
    }
    await freshPlayEntered.wait()
    let oldStopCompleted = await ownership.waitForCaptureRelease(capture)
    #expect(oldStopCompleted, "A later Play transition must not delay Stop's own completion")
    finishFreshPlay.fire()
    let explicitResult = try await explicitPlay.value
    let resumed = try #require(explicitResult)
    #expect(ownership.isCurrent(resumed))
    #expect(playbackActivationCount == 1)
  }

  @Test func reusedUnclaimedPlaybackTransfersGrantWithoutRevokingClaimedOwner() async throws {
    let ownership = PlaybackAudioOwnership()
    let requestA = UUID()
    let requestB = UUID()
    let requestC = UUID()
    var activationCount = 0
    let firstResult = try ownership.acquirePlayback(requestID: requestA,
      activate: { activationCount += 1 })
    let first = try #require(firstResult)

    // B receives the existing physical lease before A can claim it. The provisional
    // grant belongs to B now, so A's delayed post-await discard cannot revoke B.
    let secondResult = try await ownership.acquirePlayback(requestID: requestB,
      activate: { activationCount += 1 }, deactivate: {})
    let second = try #require(secondResult)
    #expect(second == first)
    #expect(activationCount == 1)
    #expect(!ownership.claimPlayback(first, requestID: requestA))
    #expect(!ownership.discardUnclaimedPlayback(first, requestID: requestA))
    #expect(ownership.isCurrent(second))
    #expect(ownership.claimPlayback(second, requestID: requestB))

    // C may reuse an already claimed active lease, but has no discard right over it.
    let thirdResult = try ownership.acquirePlayback(requestID: requestC,
      activate: { activationCount += 1 })
    let third = try #require(thirdResult)
    #expect(third == first)
    #expect(!ownership.discardUnclaimedPlayback(third, requestID: requestC))
    #expect(ownership.isCurrent(first))
    #expect(activationCount == 1)
  }

  @Test func interruptionDuringHeldActivationRequiresFreshDeliberateRequest() async throws {
    let ownership = PlaybackAudioOwnership()
    let entered = OwnershipSignal()
    let finishActivation = OwnershipSignal()
    var activationCount = 0
    let pending = Task { @MainActor in
      try await ownership.acquirePlayback(requestID: UUID(), activate: {
        activationCount += 1
        entered.fire()
        await finishActivation.wait()
      }, deactivate: {})
    }

    await entered.wait()
    ownership.beginInterruption()
    ownership.endInterruption()
    finishActivation.fire()
    let pendingResult = try await pending.value
    #expect(pendingResult == nil)
    #expect(activationCount == 1)
    let resumedResult = try await ownership.acquirePlayback(requestID: UUID(),
      activate: { activationCount += 1 }, deactivate: {})
    let resumed = try #require(resumedResult)
    #expect(ownership.isCurrent(resumed))
    #expect(activationCount == 2)
  }
}
