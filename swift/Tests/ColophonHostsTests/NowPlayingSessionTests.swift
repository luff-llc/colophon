import Foundation
import os
import Testing
@testable import ColophonHosts
@testable import ColophonListeningKit
import ColophonSession

/// `NowPlayingSession` over real endpoints of two members of a local account, an in-memory carrier and a manual clock
/// (the fast policy, so lapses and gates are short): every transition the kit adds to the cell, and that the app is
/// told to pause exactly once per loss of the role.
@MainActor @Suite(.serialized) struct NowPlayingSessionTests {
    /// One device: its session, the events it heard (with whether a `pass` had left the device when each arrived), and
    /// its store.
    @MainActor final class Player {
        let name: String
        let session: NowPlayingSession
        let store: any ClaimStore
        let log: Log<CellHostEvent>
        var events: [NowPlayingEvent] = []
        /// For each `pause`, whether the cell host had sent a `pass` frame by then.
        var passSentAtPause: [Bool] = []
        init(_ name: String, _ session: NowPlayingSession, store: any ClaimStore, log: Log<CellHostEvent>) {
            self.name = name; self.session = session; self.store = store; self.log = log
            session.onEvent = { [weak self] event in
                guard let self else { return }
                self.events.append(event)
                if case .pause = event { self.passSentAtPause.append(self.sent("pass") > 0) }
            }
        }
        var id: String { session.member }
        var pauses: [NowPlayingPauseReason] { events.compactMap { if case .pause(let r) = $0 { r } else { nil } } }
        func sent(_ kind: String) -> Int { log.all.filter { if case .sent(kind, _) = $0 { true } else { false } }.count }
        var holds: Bool { session.state.isHolder }
    }

    struct World {
        let clock: ManualClock
        let carrier: LoopCarrier
        let first: Device
        let second: Device
    }
    func world() async throws -> World {
        let (first, second) = try await LocalAccount.pair()
        return World(clock: ManualClock(), carrier: LoopCarrier(), first: first, second: second)
    }
    func player(_ w: World, _ device: Device, _ name: String, label: String, policy: NowPlayingHandoffPolicy = .automatic,
                store: (any ClaimStore)? = nil, restored: NowPlayingAnchor? = nil, live: Bool = true) async throws -> Player {
        let account = try device.account()
        let store = store ?? MemoryClaimStore()
        var options = NowPlayingOptions(label: label, handoffPolicy: policy, restoredAnchor: restored)
        options.cellPolicy = try fastPolicy()
        let log = Log<CellHostEvent>()
        let carrier = w.carrier
        let session = await NowPlayingSession.open(member: account.member, clock: w.clock, streamLive: live, options: options) {
            CellHostOptions(source: account, carrier: carrier.view(), namespace: "", cell: "", store: store)
        }
        _ = session.hostForTests?.on { log.append($0) }
        await settle()
        return Player(name, session, store: store, log: log)
    }
    func anchor(_ position: Int64, rate: Int64 = 1_000, playing: Bool = true, at: Int64, episode: String = "ep-1") throws -> NowPlayingAnchor {
        try NowPlayingAnchor(episode: episode, show: "show-1", positionMs: position, ratePermille: rate, playing: playing, at: at)
    }
    /// `a` takes the free cell and plays `episode` from `position`.
    func play(_ a: Player, from position: Int64, rate: Int64 = 1_000) async throws {
        let outcome = await a.session.requestPlayback()
        guard case .play = outcome else { Issue.record("\(a.name) did not get the free cell: \(outcome)"); return }
        try a.session.update(episode: "ep-1", show: "show-1", positionMs: position, ratePermille: rate, playing: true)
        await settle()
    }
    func request(_ p: Player) -> Task<NowPlayingRequestOutcome, Never> { Task { await p.session.requestPlayback() } }
    func close(_ players: Player...) async { for p in players { p.session.close() }; await settle() }

    // MARK: Ask and pass

    @Test func anAskIsPassedAutomaticallyWithTheFinalAnchorAtTheExactPositionAndTheHolderPausesOnce() async throws {
        let w = try await world()
        let a = try await player(w, w.first, "A", label: "Kitchen iPad"), b = try await player(w, w.second, "B", label: "Car")
        try await play(a, from: 60_000, rate: 1_250)
        await eventually("B follows A") { b.session.state.holder?.id == a.id && b.session.state.lastAnchor?.positionMs == 60_000 }
        #expect(b.session.state.holder?.label == "Kitchen iPad")
        await w.clock.advance(4_000)
        let expected: Int64 = 60_000 + 1_250 * 4_000 / 1_000
        let outcome = await request(b).value
        guard case .play(let start?) = outcome else { Issue.record("B: \(outcome)"); return }
        #expect(start.source == .passed(from: a.id))
        #expect(start.positionMs == expected && !start.anchor.playing && start.anchor.ratePermille == 1_250)
        #expect(start.projection?.errorBoundMs == 0)
        // A paused exactly once, before its pass left the device, and published the stopped anchor first.
        #expect(a.pauses == [.passed(to: NowPlayingMember(id: b.id, label: "Car", isThisDevice: false))])
        #expect(a.passSentAtPause == [false])
        #expect(a.session.state.localAnchor?.positionMs == expected && a.session.state.localAnchor?.playing == false)
        #expect(!a.holds && b.holds)
        // B plays on from there; A follows B.
        await eventually("A follows B") { a.session.state.holder?.id == b.id && a.session.state.lastAnchor?.playing == true }
        #expect(a.session.state.lastAnchor?.positionMs == expected)
        await w.clock.advance(2_000)
        #expect(a.pauses.count == 1 && b.pauses.isEmpty)
        #expect(a.session.state.writesPassiveProgress == false && b.session.state.writesPassiveProgress)
        await close(a, b)
    }

    @Test func withPromptTheHolderDecidesItDeclinesOnceAndPassesTheNextAsk() async throws {
        let w = try await world()
        let a = try await player(w, w.first, "A", label: "Kitchen iPad", policy: .prompt), b = try await player(w, w.second, "B", label: "Car")
        try await play(a, from: 10_000)
        await eventually { b.session.state.holder?.id == a.id }
        let first = request(b)
        await eventually("A is asked") { a.events.contains { if case .askReceived(let m) = $0 { m.id == b.id } else { false } } }
        #expect(a.session.state.asks.map(\.id) == [b.id] && b.session.state.requesting)
        a.session.decline(b.id)
        guard case .declined(let by) = await first.value else { Issue.record("B was not declined"); return }
        #expect(by.id == a.id && by.label == "Kitchen iPad")
        #expect(a.holds && a.pauses.isEmpty && a.session.state.asks.isEmpty)
        // The asker does not take after a decline, even once its ask has timed out.
        await w.clock.advance(1_000)
        #expect(a.holds && !b.holds)

        await w.clock.advance(1_000)
        let second = request(b)
        await eventually("A is asked again") { a.session.state.asks.map(\.id) == [b.id] }
        #expect(a.session.pass(to: b.id))
        guard case .play(let start?) = await second.value else { Issue.record("B did not get the pass"); return }
        #expect(start.positionMs == 12_000 && start.source == .passed(from: a.id))
        #expect(a.pauses.count == 1 && !a.holds && b.holds)
        #expect(!a.session.pass(to: b.id), "no second pass")
        await close(a, b)
    }

    @Test func withNeverEveryAskIsDeclined() async throws {
        let w = try await world()
        let a = try await player(w, w.first, "A", label: "Kitchen iPad", policy: .never), b = try await player(w, w.second, "B", label: "Car")
        try await play(a, from: 0)
        await eventually { b.session.state.holder?.id == a.id }
        guard case .declined = await request(b).value else { Issue.record("B was not declined"); return }
        #expect(a.holds && a.pauses.isEmpty && !a.events.contains { if case .askReceived = $0 { true } else { false } })
        await close(a, b)
    }

    // MARK: Lapse and take

    @Test func aLapsedHolderIsTakenOverFromItsLastAnchorProjectedAndTheProjectionIsCapped() async throws {
        let w = try await world()
        let a = try await player(w, w.first, "A", label: "Kitchen iPad"), b = try await player(w, w.second, "B", label: "Car")
        try await play(a, from: 100_000, rate: 1_500)
        let published = try #require(a.session.state.localAnchor)
        await eventually("B measured its offset to A") { b.session.offsetForTests(a.id) != nil && b.session.state.lastAnchor == published }
        #expect(b.session.offsetForTests(a.id)?.offset == 0)
        // A's process ends while it plays: it stops sending.
        a.session.close()
        await w.clock.advance(2_000)
        #expect(b.session.state.holderLapsed)
        let outcome = await request(b).value
        guard case .play(let start?) = outcome else { Issue.record("B: \(outcome)"); return }
        #expect(start.source == .taken(from: a.id))
        let elapsed = w.clock.mono - published.at
        #expect(start.positionMs == 100_000 + 1_500 * elapsed / 1_000)
        #expect(start.projection?.capped == false)
        #expect(b.holds && b.pauses.isEmpty)
        // The take carried the anchor re-stamped on B's clock: what B publishes keeps A's trajectory.
        #expect(b.session.state.lastAnchor?.at == w.clock.mono && b.session.state.lastAnchor?.playing == true)
        await close(b)
    }

    @Test func anAnchorOlderThanTheLimitIsProjectedOnlyToTheLimit() async throws {
        let w = try await world()
        let a = try await player(w, w.first, "A", label: "Kitchen iPad"), b = try await player(w, w.second, "B", label: "Car")
        try await play(a, from: 0)
        await eventually { b.session.offsetForTests(a.id) != nil && b.session.state.lastAnchor?.playing == true }
        a.session.close()
        await w.clock.advance(120_000)
        guard case .play(let start?) = await request(b).value else { Issue.record("B did not take"); return }
        // The fast policy's holderTimeoutMs is 1,500: the default limit is 61,500 ms.
        #expect(start.projection?.capped == true)
        #expect(start.positionMs == 61_500)
        await close(b)
    }

    // MARK: Restart

    @Test func aRestartedHolderIsGatedThenRetakesWithTheAnchorItKept() async throws {
        let w = try await world()
        let store = MemoryClaimStore()
        let a = try await player(w, w.first, "A", label: "Kitchen iPad", store: store), b = try await player(w, w.second, "B", label: "Car")
        try await play(a, from: 5_000)
        let kept = try #require(a.session.state.localAnchor)
        a.session.close()
        await settle()
        let again = try await player(w, w.first, "A2", label: "Kitchen iPad", store: store, restored: kept)
        #expect(again.holds && again.session.state.gated)
        let publishedBefore = again.sent("msg")
        await w.clock.advance(400)
        await eventually("A retakes") { !again.session.state.gated && again.holds }
        #expect(again.pauses.isEmpty)
        // It published what it is doing (the kept anchor, re-stamped), so B follows the right position.
        #expect(again.sent("msg") > publishedBefore)
        await eventually("B follows the re-stamped anchor") {
            guard let l = b.session.state.lastAnchor, l.at > kept.at else { return false }
            return l.playing && l.positionMs == kept.positionMs + (l.at - kept.at)
        }
        await close(again, b)
    }

    @Test func aRestartedHolderThatWasTakenOverYieldsAndIsToldToPauseOnce() async throws {
        let w = try await world()
        let store = MemoryClaimStore()
        let a = try await player(w, w.first, "A", label: "Kitchen iPad", store: store), b = try await player(w, w.second, "B", label: "Car")
        try await play(a, from: 5_000)
        let kept = try #require(a.session.state.localAnchor)
        a.session.close()
        await w.clock.advance(2_000)
        guard case .play = await request(b).value else { Issue.record("B did not take"); return }
        let again = try await player(w, w.first, "A2", label: "Kitchen iPad", store: store, restored: kept)
        await w.clock.advance(400)
        await eventually("A yields") { !again.holds && again.session.state.holder?.id == b.id }
        guard case .displaced(let by)? = again.pauses.first, again.pauses.count == 1 else { Issue.record("\(again.pauses)"); return }
        #expect(by?.id == b.id)
        await w.clock.advance(2_000)
        #expect(again.pauses.count == 1 && b.holds && b.pauses.isEmpty)
        // B is told what A held when it was displaced.
        await eventually { b.events.contains { if case .otherState(_, let from) = $0 { from.id == a.id } else { false } } }
        await close(again, b)
    }

    // MARK: Races

    @Test func twoDevicesPressingPlayAtOnceEndWithOneHolderAndTheOtherPausesOnce() async throws {
        let w = try await world()
        let a = try await player(w, w.first, "A", label: "Kitchen iPad"), b = try await player(w, w.second, "B", label: "Car")
        let ra = request(a), rb = request(b)
        let (oa, ob) = (await ra.value, await rb.value)
        await settle()
        await w.clock.advance(1_000)
        #expect([a.holds, b.holds].filter { $0 }.count == 1)
        let loser = a.holds ? b : a, winner = a.holds ? a : b
        #expect(loser.pauses.count == 1 && winner.pauses.isEmpty)
        if case .displaced(let by) = loser.pauses.first { #expect(by?.id == winner.id) } else { Issue.record("the loser was not displaced") }
        for o in [oa, ob] { if case .play = o {} else { Issue.record("\(o)") } }
        #expect(loser.session.state.holder?.id == winner.id && winner.session.state.holder?.id == winner.id)
        await close(a, b)
    }

    @Test func aSeekOrRateChangeBeforeTheAskIsInTheFinalAnchorAndOneAfterThePassIsNotPublished() async throws {
        let w = try await world()
        let a = try await player(w, w.first, "A", label: "Kitchen iPad"), b = try await player(w, w.second, "B", label: "Car")
        try await play(a, from: 1_000)
        await eventually { b.session.state.holder?.id == a.id }
        await w.clock.advance(500)
        // The user seeks on A and changes the rate in the same instant B's user presses Play: A's calls come first.
        let asking = request(b)
        try a.session.update(episode: "ep-1", show: "show-1", positionMs: 300_000, ratePermille: 1_500, playing: true)
        guard case .play(let start?) = await asking.value else { Issue.record("B did not get the pass"); return }
        #expect(start.positionMs == 300_000 && start.anchor.ratePermille == 1_500)
        // After the pass, A's seek is kept locally and never published: A is not "still playing here".
        let msgs = a.sent("msg")
        try a.session.update(episode: "ep-1", show: "show-1", positionMs: 400_000, ratePermille: 1_000, playing: true)
        await settle()
        await w.clock.advance(1_000)
        #expect(a.sent("msg") == msgs && !a.holds && a.session.state.localAnchor?.positionMs == 400_000)
        #expect(b.session.state.lastAnchor?.positionMs == 300_000)
        #expect(a.pauses.count == 1)
        await close(a, b)
    }

    @Test func thePauseIsReportedOncePerLossOfTheRole() async throws {
        let w = try await world()
        let a = try await player(w, w.first, "A", label: "Kitchen iPad"), b = try await player(w, w.second, "B", label: "Car")
        try await play(a, from: 0)
        await eventually { b.session.state.holder?.id == a.id }
        guard case .play = await request(b).value else { Issue.record("B did not get the pass"); return }
        await eventually { a.session.state.holder?.id == b.id }
        guard case .play = await request(a).value else { Issue.record("A did not get the pass back"); return }
        await eventually { b.session.state.holder?.id == a.id }
        guard case .play = await request(b).value else { Issue.record("B did not get the pass again"); return }
        await w.clock.advance(3_000)
        #expect(a.pauses.count == 2 && b.pauses.count == 1)
        #expect(a.pauses.allSatisfy { if case .passed = $0 { true } else { false } })
        await close(a, b)
    }

    // MARK: Fail-safe

    @Test func withTheStreamDownHandoffIsUnavailableAndLocalPlaybackGoesOn() async throws {
        let w = try await world()
        let a = try await player(w, w.first, "A", label: "Kitchen iPad"), b = try await player(w, w.second, "B", label: "Car")
        try await play(a, from: 0)
        await eventually { b.session.state.lastAnchor?.playing == true }
        a.session.streamChanged(live: false); b.session.streamChanged(live: false)
        await eventually { b.session.state.availability == .unavailable(.streamDown) && a.session.state.availability == .unavailable(.streamDown) }
        #expect(b.events.contains(.availabilityChanged(.unavailable(.streamDown))))
        // B plays locally at once, from what it knew.
        guard case .playLocally(.streamDown, let start?) = await request(b).value else { Issue.record("B was blocked"); return }
        #expect(start.anchor.positionMs == 0)
        #expect(b.session.state.writesPassiveProgress)
        // A keeps playing locally and keeps the role; nothing tells it to pause.
        try a.session.update(episode: "ep-2", show: "show-1", positionMs: 9_000, playing: true)
        #expect(a.holds && a.pauses.isEmpty && a.session.state.localAnchor?.episode == "ep-2")
        a.session.streamChanged(live: true); b.session.streamChanged(live: true)
        await eventually { a.session.state.availability == .available && b.session.state.availability == .available }
        await close(a, b)
    }

    @Test func aFailedCellTellsTheHolderToPauseOnceAndLocalPlaybackStaysOpen() async throws {
        let w = try await world()
        let store = TestStore(clock: w.clock)
        let a = try await player(w, w.first, "A", label: "Kitchen iPad", store: store)
        try await play(a, from: 0)
        store.set { $0.fenceFailures = 100 }
        await w.clock.advance(400 * 4)
        await eventually { a.session.state.availability == .unavailable(.cellFailed("store")) }
        #expect(a.pauses == [.failed("store")])
        try a.session.update(episode: "ep-1", show: "show-1", positionMs: 1_000, playing: true)
        guard case .playLocally(.cellFailed("store"), _) = await request(a).value else { Issue.record("A was blocked"); return }
        await w.clock.advance(2_000)
        #expect(a.pauses.count == 1)
        await close(a)
    }

    @Test func aSecondInstanceOfTheAppSupersedesTheFirstWhichPauses() async throws {
        let w = try await world()
        let store = MemoryClaimStore()
        let a = try await player(w, w.first, "A", label: "Kitchen iPad", store: store)
        try await play(a, from: 0)
        let other = try await player(w, w.first, "A'", label: "Kitchen iPad", store: store)
        await w.clock.advance(800)
        await eventually { a.session.state.availability == .unavailable(.cellFailed("superseded")) }
        #expect(a.pauses == [.superseded])
        await close(a, other)
    }

    @Test func aCellThatCannotBeJoinedReportsWhyAndNeverBlocksPlayback() async throws {
        let w = try await world()
        struct NoStore: Error {}
        let session = await NowPlayingSession.open(member: "m", clock: w.clock, streamLive: true, options: NowPlayingOptions(label: "Car")) { throw NoStore() }
        guard case .unavailable(.couldNotJoin) = session.state.availability else { Issue.record("\(session.state.availability)"); return }
        try session.update(episode: "ep-1", show: "show-1", positionMs: 5, playing: true)
        guard case .playLocally(.couldNotJoin, let start?) = await session.requestPlayback() else { Issue.record("blocked"); return }
        #expect(start.source == .local && start.positionMs == 5)
        session.close()
    }
}
