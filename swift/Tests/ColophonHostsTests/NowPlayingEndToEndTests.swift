import Foundation
import os
import Testing
@testable import ColophonHosts
@testable import ColophonListeningKit
import ColophonSession

/// The `now-playing` cell end to end through the listening kit's public API: two members of one account, each with its
/// own `HomeStreamHost` over a real `URLSessionWebSocketTask` to a real home (relay/server.js on Bun with the Rust home
/// module built from this tree), its own SQLite claim store, and the system clock.
@MainActor @Suite(.serialized) struct NowPlayingEndToEndTests {
    /// A plays at 1.25×; B's user presses Play: B asks, A pauses and passes, B starts from A's exact stopped position.
    @Test func bRequestsPlaybackWhileAPlaysAndStartsFromAsExactStoppedPositionWhileAPauses() async throws {
        let (relay, a, b) = try await world()
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("colophon-now-playing-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { a.close(); b.close(); relay.stop(); try? FileManager.default.removeItem(at: dir) }
        try await a.startStream(); try await b.startStream()
        try await a.when("A's stream is live") { await a.stream.live }
        try await b.when("B's stream is live") { await b.stream.live }

        let npA = await NowPlayingSession.open(session: a.device.session, stream: a.stream, claimsDatabase: dir.appendingPathComponent("a.sqlite"),
                                               options: NowPlayingOptions(label: "Kitchen iPad"))
        let npB = await NowPlayingSession.open(session: b.device.session, stream: b.stream, claimsDatabase: dir.appendingPathComponent("b.sqlite"),
                                               options: NowPlayingOptions(label: "Car"))
        defer { npA.close(); npB.close() }
        try await a.when("A's cell is available") { npA.state.availability == .available }
        try await b.when("B's cell is available") { npB.state.availability == .available }
        let pauses = OSAllocatedUnfairLockBox<[(at: Double, reason: NowPlayingPauseReason, stopped: NowPlayingAnchor?)]>([])
        npA.onEvent = { [npA] event in
            if case .pause(let reason) = event { pauses.set(pauses.get() + [(nowMs(), reason, npA.state.localAnchor)]) }
        }

        // A plays: nobody holds the cell, so A takes it; then its audio starts at 1,234,567 ms, 1.25×.
        guard case .play = await npA.requestPlayback() else { Issue.record("A did not take the free cell"); return }
        try npA.update(episode: "ep-1", show: "show-1", positionMs: 1_234_567, ratePermille: 1_250, playing: true)
        let playing = try #require(npA.state.localAnchor)
        try await b.when("B follows A's anchor and has measured its offset to A") {
            npB.state.holder?.id == a.id && npB.state.lastAnchor == playing && npB.offsetForTests(a.id) != nil
        }
        try await b.when("B knows A's label") { npB.state.holder?.label == "Kitchen iPad" }
        try await Task.sleep(for: .milliseconds(700))

        // While following: B's projection of A's position against A's own, at one instant. Both run in this process on
        // one CLOCK_MONOTONIC, so the true offset is 0 and the difference is the translation's whole error.
        let (offset, error) = try #require(npB.offsetForTests(a.id))
        let now = SystemClock().monoMs()
        let onB = playing.projected(nowMs: now, clock: NowPlayingClockOffset(offsetMs: offset, errorMs: error, sampleAgeMs: 0), maximumProjectionMs: 75_000)
        let onA = playing.projected(nowMs: now, maximumProjectionMs: 75_000)
        let followError = abs(onB.positionMs - onA.positionMs)
        #expect(followError <= onB.errorBoundMs, "B's projection is within the bound it reports")

        // B's user presses Play.
        let pressed = nowMs()
        let outcome = await npB.requestPlayback()
        let started = nowMs(), startedMono = SystemClock().monoMs()
        guard case .play(let start?) = outcome else { Issue.record("B: \(outcome)"); return }
        try await a.when("A is told to pause") { !pauses.get().isEmpty }
        let pause = try #require(pauses.get().first)
        let stopped = try #require(pause.stopped)
        #expect(pause.reason == .passed(to: NowPlayingMember(id: b.id, label: "Car", isThisDevice: false)))
        #expect(start.source == .passed(from: a.id))
        // §S12: the new holder starts from the passed position exactly.
        let positionError = start.positionMs - stopped.positionMs
        #expect(positionError == 0 && !stopped.playing)
        // Against A's uninterrupted trajectory at the instant B started, the only difference is the handoff's own time.
        let trajectory = playing.projected(nowMs: startedMono, maximumProjectionMs: 75_000).positionMs
        let behindTrajectory = trajectory - start.positionMs
        print(String(format: "now-playing handoff (real home, URLSessionWebSocketTask): B's request -> A's pause event %.1f ms; -> B's start %.1f ms; "
                     + "position error vs A's stopped position %lld ms; B starts %lld ms behind A's uninterrupted 1.25x trajectory; "
                     + "while following, B's projection was %lld ms from A's (bound %lld ms, offset %lld ms, error %lld ms)",
                     pause.at - pressed, started - pressed, positionError, behindTrajectory, followError, onB.errorBoundMs, offset, error))
        #expect(npB.state.isHolder && !npA.state.isHolder)
        #expect(started - pressed < 1_000)

        // A follows B, which plays on from that position; A is told to pause exactly once and sends nothing as holder.
        try await a.when("A follows B") { npA.state.holder?.id == b.id && npA.state.lastAnchor?.playing == true }
        #expect(npA.state.lastAnchor?.positionMs == stopped.positionMs)
        try await Task.sleep(for: .milliseconds(1_000))
        #expect(pauses.get().count == 1)
        #expect(npA.state.writesPassiveProgress == false && npB.state.writesPassiveProgress)
    }
}
